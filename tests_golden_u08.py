#!/usr/bin/env python
"""Golden (characterization) tests for U08: app/models.py User.set_password.

These pin the CURRENT behaviour (Werkzeug 3.0.1) so a dependency upgrade can
be checked for zero behaviour change. They do not describe intended behaviour.
"""
import re
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


FIXED_SALT = 'abcdefghijklmnop'
HASH_PREFIX = 'scrypt:32768:8:1$' + FIXED_SALT + '$'
HASH_FORMAT = re.compile(r'^scrypt:32768:8:1\$[A-Za-z0-9]{16}\$[0-9a-f]{128}$')

GOLDEN_HASHES = {
    'cat': HASH_PREFIX + (
        'f7d55d9132b0f875bf2fb66b14881b3c31f6c2d1c08153002301c5555da3903e'
        '533bcc82c243fbbcc67d1c8c27b6831cc503df40c8b752adf6073f1c8e26b134'),
    '': HASH_PREFIX + (
        '6f0399f0736cd2d652d2142d8ad5a11b4b817abb28dce23c9433a97db068c535'
        '40bba1faec75aebf19cec81dde3865a92ee3795e9cf72ef90537346706b39e24'),
    'cat ': HASH_PREFIX + (
        '283ad735b1d4c603c40ce28e6f0460d46c305e4954230eae68f07b3659d70d9a'
        '6ccff31356520ad972eb2824a351453cf7e18fdc48a9a8b3993f7b7f1c81c78f'),
    'p\u00e4ssw\u00f6rd': HASH_PREFIX + (
        '2f47557ac9cfd214bb1eed7164231aaf185a03ce6f96d71ddd17b1689fc81071'
        'e2c607e1ec25cd0c2e50a60c139abb5b568c55ab687970c81c66835eae180e0c'),
    'a' * 1000: HASH_PREFIX + (
        'd38842048b70b434983bb155423a2e00eb61106ad539a1e6e99d633f02e0d4f9'
        '7d2479768241202f819876a179a34e3e443eed96acdba8248cff92b30f568274'),
    'a\x00b': HASH_PREFIX + (
        'e2ceae9d63729883a80347dc28284822d74889de8f93bd5453a091a6b7b9cf09'
        '30778b8266849861361505bfd6d2e01b17aa32754f117987f936404be621fc29'),
}


class SetPasswordGoldenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _user(self):
        return User(username='susan', email='susan@example.com')

    def _set_with_fixed_salt(self, user, password):
        with mock.patch('werkzeug.security.gen_salt',
                        return_value=FIXED_SALT) as gen_salt:
            result = user.set_password(password)
        return result, gen_salt

    # --- delegation to werkzeug -------------------------------------------

    def test_delegates_to_generate_password_hash_with_password_only(self):
        u = self._user()
        with mock.patch('app.models.generate_password_hash',
                        return_value='HASHED') as gph:
            result = u.set_password('cat')
        gph.assert_called_once_with('cat')
        self.assertEqual(gph.call_args.kwargs, {})
        self.assertIsNone(result)
        self.assertEqual(u.password_hash, 'HASHED')

    def test_stores_return_value_verbatim(self):
        u = self._user()
        sentinel = object()
        with mock.patch('app.models.generate_password_hash',
                        return_value=sentinel):
            u.set_password('cat')
        self.assertIs(u.password_hash, sentinel)

    def test_password_passed_through_unmodified(self):
        u = self._user()
        with mock.patch('app.models.generate_password_hash',
                        return_value='H') as gph:
            u.set_password('  Cat \n')
        gph.assert_called_once_with('  Cat \n')

    # --- exact hash values (default scrypt, salt_length 16) -----------------

    def test_exact_hash_for_normal_password(self):
        u = self._user()
        result, gen_salt = self._set_with_fixed_salt(u, 'cat')
        self.assertIsNone(result)
        gen_salt.assert_called_once_with(16)
        self.assertEqual(u.password_hash, GOLDEN_HASHES['cat'])
        self.assertIsInstance(u.password_hash, str)
        self.assertEqual(len(u.password_hash), 162)

    def test_exact_hash_for_empty_password(self):
        # Current behaviour that looks like a bug: an empty password is
        # accepted and hashed; set_password does no validation.
        u = self._user()
        self._set_with_fixed_salt(u, '')
        self.assertEqual(u.password_hash, GOLDEN_HASHES[''])
        self.assertTrue(u.check_password(''))

    def test_whitespace_is_not_stripped(self):
        u = self._user()
        self._set_with_fixed_salt(u, 'cat ')
        self.assertEqual(u.password_hash, GOLDEN_HASHES['cat '])
        self.assertNotEqual(u.password_hash, GOLDEN_HASHES['cat'])
        self.assertFalse(u.check_password('cat'))
        self.assertTrue(u.check_password('cat '))

    def test_non_ascii_password_hashed_as_utf8(self):
        u = self._user()
        self._set_with_fixed_salt(u, 'p\u00e4ssw\u00f6rd')
        self.assertEqual(u.password_hash, GOLDEN_HASHES['p\u00e4ssw\u00f6rd'])

    def test_long_password_not_truncated(self):
        # Current behaviour that looks like a bug: no maximum length, so a
        # 1000-character password is hashed in full.
        u = self._user()
        self._set_with_fixed_salt(u, 'a' * 1000)
        self.assertEqual(u.password_hash, GOLDEN_HASHES['a' * 1000])
        self.assertFalse(u.check_password('a' * 999))

    def test_null_byte_in_password_accepted(self):
        # Current behaviour that looks like a bug: embedded NUL characters
        # are accepted and are significant.
        u = self._user()
        self._set_with_fixed_salt(u, 'a\x00b')
        self.assertEqual(u.password_hash, GOLDEN_HASHES['a\x00b'])
        self.assertFalse(u.check_password('a'))

    # --- real randomness / format -----------------------------------------

    def test_hash_format_and_random_salt(self):
        u = self._user()
        u.set_password('cat')
        first = u.password_hash
        self.assertRegex(first, HASH_FORMAT)
        self.assertEqual(len(first), 162)
        self.assertLessEqual(len(first), 256)  # password_hash is String(256)
        u.set_password('cat')
        second = u.password_hash
        self.assertRegex(second, HASH_FORMAT)
        self.assertNotEqual(first, second)
        self.assertTrue(u.check_password('cat'))
        self.assertFalse(u.check_password('dog'))

    def test_overwrites_previous_hash(self):
        u = self._user()
        u.set_password('cat')
        self.assertTrue(u.check_password('cat'))
        u.set_password('dog')
        self.assertTrue(u.check_password('dog'))
        self.assertFalse(u.check_password('cat'))

    # --- error paths --------------------------------------------------------

    def test_none_raises_attribute_error_and_keeps_hash(self):
        # Current behaviour that looks like a bug: None leaks an
        # AttributeError from werkzeug instead of a clear validation error.
        u = self._user()
        self._set_with_fixed_salt(u, 'cat')
        with self.assertRaises(AttributeError) as cm:
            u.set_password(None)
        self.assertEqual(str(cm.exception),
                         "'NoneType' object has no attribute 'encode'")
        self.assertEqual(u.password_hash, GOLDEN_HASHES['cat'])

    def test_none_on_fresh_user_leaves_hash_none(self):
        u = self._user()
        with self.assertRaises(AttributeError):
            u.set_password(None)
        self.assertIsNone(u.password_hash)

    def test_bytes_raises_attribute_error(self):
        # Current behaviour that looks like a bug: bytes passwords are
        # rejected with an AttributeError rather than being accepted.
        u = self._user()
        with self.assertRaises(AttributeError) as cm:
            u.set_password(b'cat')
        self.assertEqual(str(cm.exception),
                         "'bytes' object has no attribute 'encode'")
        self.assertIsNone(u.password_hash)

    def test_int_raises_attribute_error(self):
        u = self._user()
        with self.assertRaises(AttributeError) as cm:
            u.set_password(123)
        self.assertEqual(str(cm.exception),
                         "'int' object has no attribute 'encode'")
        self.assertIsNone(u.password_hash)

    # --- DB side effects ----------------------------------------------------

    def test_does_not_add_transient_user_to_session(self):
        u = self._user()
        u.set_password('cat')
        self.assertNotIn(u, db.session)
        self.assertEqual(db.session.scalar(
            sa.select(sa.func.count()).select_from(User)), 0)

    def test_does_not_commit(self):
        u = self._user()
        self._set_with_fixed_salt(u, 'cat')
        db.session.add(u)
        db.session.commit()
        self._set_with_fixed_salt(u, 'dog')
        self.assertIn(u, db.session.dirty)
        db.session.rollback()
        self.assertEqual(u.password_hash, GOLDEN_HASHES['cat'])

    def test_persists_after_caller_commits(self):
        u = self._user()
        self._set_with_fixed_salt(u, 'cat')
        db.session.add(u)
        db.session.commit()
        db.session.expire_all()
        stored = db.session.scalar(
            sa.select(User.password_hash).where(User.username == 'susan'))
        self.assertEqual(stored, GOLDEN_HASHES['cat'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
