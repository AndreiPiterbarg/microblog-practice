#!/usr/bin/env python
"""Golden (characterization) tests for U04: app/models.py User.avatar.

These pin the CURRENT behaviour of User.avatar so a fix for ruff S324
(md5 usage) can be checked for zero behaviour change. Digests are
hard-coded literals, not recomputed with hashlib, so any change to the
hashing, normalisation or URL format makes these tests fail.
"""
import unittest
from unittest import mock
from app import create_app, db
from app.models import User
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


GRAVATAR = 'https://www.gravatar.com/avatar/'
JOHN_DIGEST = 'd4c74594d841139328695756648b6bd6'


class UserAvatarGoldenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    # --- normal cases -----------------------------------------------------

    def test_exact_url_for_known_email(self):
        u = User(username='john', email='john@example.com')
        self.assertEqual(
            u.avatar(128),
            GRAVATAR + JOHN_DIGEST + '?d=identicon&s=128')

    def test_return_type_is_str(self):
        u = User(username='john', email='john@example.com')
        self.assertIs(type(u.avatar(128)), str)

    def test_sizes_used_by_templates_and_api(self):
        u = User(username='john', email='john@example.com')
        for size in (64, 70, 128, 256):
            self.assertEqual(
                u.avatar(size),
                f'{GRAVATAR}{JOHN_DIGEST}?d=identicon&s={size}')

    def test_digest_is_md5_hex_of_lowercased_utf8_email(self):
        u = User(username='john', email='john@example.com')
        url = u.avatar(1)
        digest = url[len(GRAVATAR):url.index('?')]
        self.assertEqual(len(digest), 32)
        self.assertEqual(digest, digest.lower())
        self.assertEqual(digest, JOHN_DIGEST)

    # --- edge cases: email normalisation -----------------------------------

    def test_email_is_lowercased_before_hashing(self):
        u = User(username='john', email='JOHN@Example.COM')
        self.assertEqual(
            u.avatar(128),
            GRAVATAR + JOHN_DIGEST + '?d=identicon&s=128')

    def test_email_attribute_not_mutated(self):
        u = User(username='john', email='JOHN@Example.COM')
        u.avatar(128)
        self.assertEqual(u.email, 'JOHN@Example.COM')

    def test_surrounding_whitespace_is_not_stripped(self):
        # Current behaviour that looks like a bug: Gravatar expects the
        # email trimmed before hashing, but whitespace is hashed as-is,
        # giving a different digest than 'john@example.com'.
        u = User(username='john', email=' john@example.com ')
        self.assertEqual(
            u.avatar(128),
            GRAVATAR + '9b953676d768693666a06cf13d5ced87'
            '?d=identicon&s=128')

    def test_trailing_newline_is_not_stripped(self):
        # Current behaviour that looks like a bug: trailing newline is
        # hashed as part of the email.
        u = User(username='john', email='john@example.com\n')
        self.assertEqual(
            u.avatar(128),
            GRAVATAR + '6b8d6e2e129a2f2ce3dc0a2e9ebdbdf1'
            '?d=identicon&s=128')

    def test_empty_email_hashes_empty_string(self):
        # Current behaviour that looks like a bug: no validation, an empty
        # email yields the md5 of b'' instead of an error.
        u = User(username='nobody', email='')
        self.assertEqual(
            u.avatar(128),
            GRAVATAR + 'd41d8cd98f00b204e9800998ecf8427e'
            '?d=identicon&s=128')

    def test_non_ascii_email_lowercased_and_utf8_encoded(self):
        upper = User(username='u1', email='ÜSER@example.com')
        lower = User(username='u2', email='üser@example.com')
        expected = (GRAVATAR + 'e52198ce0afea59d08015a28cb6d044e'
                    '?d=identicon&s=80')
        self.assertEqual(upper.avatar(80), expected)
        self.assertEqual(lower.avatar(80), expected)

    def test_turkish_dotted_capital_i_lowercases_to_two_code_points(self):
        # Current behaviour that looks like a bug: str.lower() (not
        # casefold/ASCII-only lowering) turns 'İ' into 'i' + U+0307.
        u = User(username='t', email='İ@example.com')
        self.assertEqual(
            u.avatar(80),
            GRAVATAR + '920ce4fe9ed68547518bbf0bd8fd9ad1'
            '?d=identicon&s=80')

    # --- edge cases: size is not validated ---------------------------------

    def test_size_zero_and_negative_passed_through(self):
        # Current behaviour that looks like a bug: no range check on size.
        u = User(username='john', email='john@example.com')
        self.assertEqual(u.avatar(0),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=0')
        self.assertEqual(u.avatar(-1),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=-1')

    def test_large_size_passed_through(self):
        # Current behaviour that looks like a bug: no upper bound on size.
        u = User(username='john', email='john@example.com')
        self.assertEqual(u.avatar(100000),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=100000')

    def test_non_int_sizes_formatted_with_str(self):
        # Current behaviour that looks like a bug: any object is accepted
        # and interpolated via str(), unescaped.
        u = User(username='john', email='john@example.com')
        self.assertEqual(u.avatar('128'),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=128')
        self.assertEqual(u.avatar(1.5),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=1.5')
        self.assertEqual(u.avatar(None),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=None')
        self.assertEqual(u.avatar(True),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=True')
        self.assertEqual(u.avatar('1&d=mp'),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=1&d=mp')

    # --- error paths -------------------------------------------------------

    def test_missing_size_raises_type_error(self):
        u = User(username='john', email='john@example.com')
        with self.assertRaises(TypeError):
            u.avatar()

    def test_none_email_raises_attribute_error(self):
        # Current behaviour that looks like a bug: unhandled crash when
        # email is unset.
        u = User(username='john')
        with self.assertRaises(AttributeError) as cm:
            u.avatar(128)
        self.assertIn("'NoneType' object has no attribute 'lower'",
                      str(cm.exception))

    def test_bytes_email_raises_attribute_error(self):
        u = User(username='john', email=b'john@example.com')
        with self.assertRaises(AttributeError) as cm:
            u.avatar(128)
        self.assertIn("'bytes' object has no attribute 'encode'",
                      str(cm.exception))

    # --- side effects ------------------------------------------------------

    def test_no_db_write_and_works_for_transient_user(self):
        u = User(username='john', email='john@example.com')
        self.assertEqual(u.avatar(128),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=128')
        self.assertNotIn(u, db.session)
        self.assertEqual(db.session.scalar(
            db.select(db.func.count()).select_from(User)), 0)

    def test_persisted_user_no_pending_changes(self):
        u = User(username='john', email='john@example.com')
        db.session.add(u)
        db.session.commit()
        self.assertEqual(u.avatar(64),
                         GRAVATAR + JOHN_DIGEST + '?d=identicon&s=64')
        self.assertFalse(db.session.dirty)
        self.assertFalse(db.session.new)

    def test_no_network_access(self):
        u = User(username='john', email='john@example.com')
        with mock.patch('socket.socket') as sock, \
                mock.patch('requests.get') as get, \
                mock.patch('requests.post') as post:
            u.avatar(128)
        sock.assert_not_called()
        get.assert_not_called()
        post.assert_not_called()

    def test_deterministic_across_calls(self):
        u = User(username='john', email='john@example.com')
        self.assertEqual(u.avatar(128), u.avatar(128))


if __name__ == '__main__':
    unittest.main(verbosity=2)
