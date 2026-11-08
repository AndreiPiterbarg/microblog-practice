#!/usr/bin/env python
"""Golden (characterization) tests for U09: app/models.py User.check_password.

These pin the CURRENT behaviour of User.check_password (a thin wrapper around
werkzeug.security.check_password_hash, Werkzeug==3.0.1) so that dependency
upgrades can be checked for behaviour changes. They do not test intended
behaviour.
"""
import unittest
from unittest import mock
import sqlalchemy as sa
from app import create_app, db
from app.models import User
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


# Hashes generated once with Werkzeug 3.0.1 generate_password_hash and frozen.
SCRYPT_DEFAULT_CAT = (
    'scrypt:32768:8:1$XrWOM2FVg6EvWGux$ab1a938d195578fe1c240a9347afc00988407c'
    '5430eefceb07f39dcc06908d446204dc6903b3b9a43dbb03929f61445995f7c4c351094f'
    '578ea1c80c6c9b32d1')
PBKDF2_SHA256_CAT = (
    'pbkdf2:sha256:1000$aig5cRPn$850c93915002466b96f7d461ad5d3ab1ef0fcf079c63'
    'a4e6f0320cce703a239a')
PBKDF2_SHA256_EMPTY = (
    'pbkdf2:sha256:1000$G9CuO6HW$b8f773db6836989b046300e41c7a4d24d795f1215105'
    'fd8088abed4f61bf3a57')
PBKDF2_SHA1_CAT = (
    'pbkdf2:sha1:1000$8Gy43DZ5$b3cacf4c0cceb2c906be77616700d45e61f26162')
SCRYPT_LOWCOST_UNICODE = (
    'scrypt:1024:8:1$UHiyvD80$8ca42f04ced7ee993553174fc9c94785116beedba66347'
    '487ca89c5fdc6cdc99ce957a9ab8c1cc3014d9cc1fdae212a830e857f56b9f61735483b1'
    'd2734813ae')
UNICODE_PASSWORD = 'p\u00e4ssw\u00f6rd\u2713'


class CheckPasswordGoldenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _user(self, password_hash=None):
        u = User(username='susan', email='susan@example.com')
        u.password_hash = password_hash
        return u

    # --- delegation -------------------------------------------------------

    def test_delegates_to_werkzeug_with_exact_args_and_returns_result(self):
        u = self._user('stored-hash')
        sentinel = object()
        with mock.patch('app.models.check_password_hash',
                        return_value=sentinel) as m:
            result = u.check_password('cat')
        m.assert_called_once_with('stored-hash', 'cat')
        self.assertIs(result, sentinel)

    def test_return_value_is_passed_through_without_bool_coercion(self):
        # Current behaviour: no bool() wrapping, whatever werkzeug returns
        # is returned as-is.
        u = self._user('stored-hash')
        with mock.patch('app.models.check_password_hash', return_value=0):
            self.assertEqual(u.check_password('cat'), 0)
        with mock.patch('app.models.check_password_hash', return_value=None):
            self.assertIsNone(u.check_password('cat'))

    def test_exception_from_werkzeug_propagates(self):
        u = self._user('stored-hash')
        with mock.patch('app.models.check_password_hash',
                        side_effect=RuntimeError('boom')):
            with self.assertRaises(RuntimeError) as cm:
                u.check_password('cat')
        self.assertEqual(str(cm.exception), 'boom')

    # --- normal cases with real werkzeug ----------------------------------

    def test_round_trip_with_set_password(self):
        u = self._user()
        u.set_password('cat')
        self.assertIs(u.check_password('cat'), True)
        self.assertIs(u.check_password('dog'), False)

    def test_frozen_default_scrypt_hash(self):
        u = self._user(SCRYPT_DEFAULT_CAT)
        self.assertIs(u.check_password('cat'), True)
        self.assertIs(u.check_password('dog'), False)

    def test_frozen_legacy_pbkdf2_sha256_hash(self):
        u = self._user(PBKDF2_SHA256_CAT)
        self.assertIs(u.check_password('cat'), True)
        self.assertIs(u.check_password('dog'), False)

    def test_frozen_legacy_pbkdf2_sha1_hash(self):
        u = self._user(PBKDF2_SHA1_CAT)
        self.assertIs(u.check_password('cat'), True)
        self.assertIs(u.check_password('cats'), False)

    def test_frozen_unicode_password_hash(self):
        u = self._user(SCRYPT_LOWCOST_UNICODE)
        self.assertIs(u.check_password(UNICODE_PASSWORD), True)
        self.assertIs(u.check_password('passwords'), False)

    def test_empty_password_matches_hash_of_empty_password(self):
        u = self._user(PBKDF2_SHA256_EMPTY)
        self.assertIs(u.check_password(''), True)
        self.assertIs(u.check_password(' '), False)

    def test_comparison_is_exact(self):
        u = self._user(PBKDF2_SHA256_CAT)
        for wrong in ['Cat', 'CAT', 'cat ', ' cat', 'ca', 'catt', '']:
            with self.subTest(password=wrong):
                self.assertIs(u.check_password(wrong), False)

    def test_tampered_hash_value_is_false(self):
        # uppercase hex digest: compare_digest is case-sensitive
        method_salt, digest = PBKDF2_SHA256_CAT.rsplit('$', 1)
        u = self._user(method_salt + '$' + digest.upper())
        self.assertIs(u.check_password('cat'), False)
        u = self._user(PBKDF2_SHA256_CAT[:-1])
        self.assertIs(u.check_password('cat'), False)
        u = self._user(PBKDF2_SHA256_CAT + ' ')
        self.assertIs(u.check_password('cat'), False)

    def test_no_side_effects_on_user_or_db(self):
        u = self._user()
        u.set_password('cat')
        db.session.add(u)
        db.session.commit()
        before = u.password_hash
        self.assertIs(u.check_password('cat'), True)
        self.assertIs(u.check_password('dog'), False)
        self.assertEqual(u.password_hash, before)
        self.assertNotIn(u, db.session.dirty)
        stored = db.session.scalar(
            sa.select(User.password_hash).where(User.id == u.id))
        self.assertEqual(stored, before)

    def test_works_after_reload_from_db(self):
        u = self._user(PBKDF2_SHA256_CAT)
        db.session.add(u)
        db.session.commit()
        uid = u.id
        db.session.expunge_all()
        reloaded = db.session.get(User, uid)
        self.assertIs(reloaded.check_password('cat'), True)
        self.assertIs(reloaded.check_password('dog'), False)

    # --- edge / error paths (malformed stored hash) -----------------------

    def test_user_without_password_hash_raises_attribute_error(self):
        # QUIRK: current behaviour that looks like a bug - a user whose
        # password_hash is None (column is nullable, e.g. never set) makes
        # check_password raise instead of returning False.
        u = self._user(None)
        with self.assertRaises(AttributeError) as cm:
            u.check_password('cat')
        self.assertEqual(str(cm.exception),
                         "'NoneType' object has no attribute 'split'")

    def test_hash_without_two_dollar_signs_is_false(self):
        for bad in ['', 'cat', 'a$b', '$', 'scrypt:32768:8:1$onlysalt']:
            with self.subTest(password_hash=bad):
                self.assertIs(self._user(bad).check_password('cat'), False)

    def test_unknown_hash_method_raises_value_error(self):
        # QUIRK: current behaviour that looks like a bug - an unrecognised
        # method (including removed legacy 'plain'/'sha256' formats) raises
        # ValueError instead of returning False.
        cases = {
            'foo$salt$hash': "Invalid hash method 'foo'.",
            'plain$$cat': "Invalid hash method 'plain'.",
            'sha256$$x': "Invalid hash method 'sha256'.",
            '$$': "Invalid hash method ''.",
        }
        for bad, msg in cases.items():
            with self.subTest(password_hash=bad):
                with self.assertRaises(ValueError) as cm:
                    self._user(bad).check_password('cat')
                self.assertEqual(str(cm.exception), msg)

    def test_malformed_method_arguments_raise_value_error(self):
        # QUIRK: current behaviour that looks like a bug - bad method
        # parameters in the stored hash raise rather than return False.
        cases = {
            'pbkdf2:sha256:abc$s$x':
                "invalid literal for int() with base 10: 'abc'",
            'pbkdf2:sha256:1:2$s$x': "'pbkdf2' takes 2 arguments.",
            'scrypt:1:2$s$x': "'scrypt' takes 3 arguments.",
        }
        for bad, msg in cases.items():
            with self.subTest(password_hash=bad):
                with self.assertRaises(ValueError) as cm:
                    self._user(bad).check_password('cat')
                self.assertEqual(str(cm.exception), msg)

    def test_known_method_with_garbage_digest_is_false(self):
        for bad in ['pbkdf2:md5:1000$s$x', 'pbkdf2:sha256:1000$s$x',
                    'scrypt:1024:8:1$s$x']:
            with self.subTest(password_hash=bad):
                self.assertIs(self._user(bad).check_password('cat'), False)

    # --- edge / error paths (non-str password) ----------------------------

    def test_non_str_password_raises_attribute_error(self):
        # QUIRK: current behaviour that looks like a bug - bytes/None/int
        # passwords raise AttributeError (str.encode is assumed) instead of
        # returning False.
        u = self._user(PBKDF2_SHA256_CAT)
        cases = [
            (None, "'NoneType' object has no attribute 'encode'"),
            (b'cat', "'bytes' object has no attribute 'encode'"),
            (123, "'int' object has no attribute 'encode'"),
        ]
        for pw, msg in cases:
            with self.subTest(password=pw):
                with self.assertRaises(AttributeError) as cm:
                    u.check_password(pw)
                self.assertEqual(str(cm.exception), msg)

    def test_non_str_password_with_malformed_hash_is_false(self):
        # The hash is parsed before the password is touched, so a hash
        # without two '$' short-circuits to False even for None.
        self.assertIs(self._user('nodollars').check_password(None), False)


if __name__ == '__main__':
    unittest.main(verbosity=2)
