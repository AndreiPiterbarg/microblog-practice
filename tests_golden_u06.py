"""Golden (characterization) tests for U06: User.get_reset_password_token.

These pin the CURRENT behaviour of app/models.py:181-184, including quirks.
They must pass identically before and after any pyjwt upgrade.
"""
import base64
import json
import unittest
from unittest import mock

import jwt

from app import create_app, db
from app.models import User
from config import Config

FIXED_NOW = 1700000000.0
SECRET = 'you-will-never-guess'

HEADER_B64 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'

TOKEN_ID1_DEFAULT = (
    HEADER_B64 + '.'
    'eyJyZXNldF9wYXNzd29yZCI6MSwiZXhwIjoxNzAwMDAwNjAwLjB9.'
    'bv442zOsk183y-8gUD5Tl1GDwR93oDqE11P2VZTXPrE')
TOKEN_ID1_EXPIRES_60 = (
    HEADER_B64 + '.'
    'eyJyZXNldF9wYXNzd29yZCI6MSwiZXhwIjoxNzAwMDAwMDYwLjB9.'
    'zpXM1b5NWVQHQKrtufaHNjHiiwN_1icOw1vTlWJRu34')
TOKEN_UNSAVED_DEFAULT = (
    HEADER_B64 + '.'
    'eyJyZXNldF9wYXNzd29yZCI6bnVsbCwiZXhwIjoxNzAwMDAwNjAwLjB9.'
    '6dKRHzDPhUhFpgdS9AVbelGd2ILPsLwahiV0KTLRd04')
TOKEN_ID1_FRACTIONAL = (
    HEADER_B64 + '.'
    'eyJyZXNldF9wYXNzd29yZCI6MSwiZXhwIjoxNzAwMDAwMDAwLjc1fQ.'
    'ohLQrCMxPViDObKAaJxcPwbAwAdjTWah6Df1EK-_QBQ')


def b64url_decode(segment):
    return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))


def split_token(token):
    header, payload, signature = token.split('.')
    return b64url_decode(header), b64url_decode(payload), signature


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None
    SECRET_KEY = SECRET


class GetResetPasswordTokenGoldenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.user = User(username='susan', email='susan@example.com')
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def token(self, *args, now=FIXED_NOW, user=None, **kwargs):
        user = user if user is not None else self.user
        with mock.patch('app.models.time', return_value=now) as fake_time:
            result = user.get_reset_password_token(*args, **kwargs)
        self.assertEqual(fake_time.call_count, 1)
        fake_time.assert_called_once_with()
        return result

    # --- normal cases -----------------------------------------------------

    def test_default_token_exact_value(self):
        self.assertEqual(self.user.id, 1)
        self.assertEqual(self.token(), TOKEN_ID1_DEFAULT)

    def test_return_type_is_str(self):
        self.assertIs(type(self.token()), str)

    def test_header_is_hs256_jwt(self):
        header, _, _ = split_token(self.token())
        self.assertEqual(header, b'{"alg":"HS256","typ":"JWT"}')
        self.assertEqual(jwt.get_unverified_header(self.token()),
                         {'alg': 'HS256', 'typ': 'JWT'})

    def test_payload_exact_bytes_and_key_order(self):
        _, payload, _ = split_token(self.token())
        self.assertEqual(payload, b'{"reset_password":1,"exp":1700000600.0}')
        claims = json.loads(payload)
        self.assertEqual(list(claims), ['reset_password', 'exp'])

    def test_default_expiry_is_now_plus_600_as_float(self):
        claims = jwt.decode(self.token(), SECRET, algorithms=['HS256'],
                            options={'verify_exp': False})
        self.assertEqual(claims, {'reset_password': 1, 'exp': 1700000600.0})
        # Current behaviour: 'exp' is a float, not an integer NumericDate.
        self.assertIs(type(claims['exp']), float)
        self.assertIs(type(claims['reset_password']), int)

    def test_no_extra_claims(self):
        claims = jwt.decode(self.token(), SECRET, algorithms=['HS256'],
                            options={'verify_exp': False})
        self.assertNotIn('iat', claims)
        self.assertNotIn('nbf', claims)
        self.assertNotIn('sub', claims)

    def test_signature_verifies_with_secret_key(self):
        claims = jwt.decode(self.token(now=0.0, expires_in=10 ** 12),
                            SECRET, algorithms=['HS256'])
        self.assertEqual(claims, {'reset_password': 1, 'exp': 1e12})

    def test_signature_fails_with_other_key(self):
        with self.assertRaises(jwt.InvalidSignatureError):
            jwt.decode(self.token(), 'other-key', algorithms=['HS256'],
                       options={'verify_exp': False})

    def test_custom_expires_in_positional(self):
        self.assertEqual(self.token(60), TOKEN_ID1_EXPIRES_60)

    def test_custom_expires_in_keyword(self):
        self.assertEqual(self.token(expires_in=60), TOKEN_ID1_EXPIRES_60)

    def test_fractional_time_and_expires_in(self):
        token = self.token(expires_in=0.25, now=1700000000.5)
        self.assertEqual(token, TOKEN_ID1_FRACTIONAL)
        _, payload, _ = split_token(token)
        self.assertEqual(payload, b'{"reset_password":1,"exp":1700000000.75}')

    def test_deterministic_for_same_inputs(self):
        self.assertEqual(self.token(), self.token())

    def test_different_users_get_different_tokens(self):
        other = User(username='john', email='john@example.com')
        db.session.add(other)
        db.session.commit()
        self.assertEqual(other.id, 2)
        token = self.token(user=other)
        self.assertNotEqual(token, TOKEN_ID1_DEFAULT)
        _, payload, _ = split_token(token)
        self.assertEqual(payload, b'{"reset_password":2,"exp":1700000600.0}')

    # --- dependency boundary ----------------------------------------------

    def test_calls_jwt_encode_with_exact_arguments(self):
        with mock.patch('app.models.time', return_value=FIXED_NOW), \
                mock.patch('app.models.jwt.encode',
                           return_value='sentinel') as fake_encode:
            result = self.user.get_reset_password_token()
        self.assertEqual(result, 'sentinel')
        fake_encode.assert_called_once_with(
            {'reset_password': 1, 'exp': 1700000600.0},
            SECRET, algorithm='HS256')

    def test_returns_whatever_jwt_encode_returns(self):
        with mock.patch('app.models.jwt.encode', return_value=b'bytes'):
            self.assertEqual(self.user.get_reset_password_token(), b'bytes')

    def test_secret_key_is_read_at_call_time(self):
        self.app.config['SECRET_KEY'] = 'rotated-key'
        token = self.token()
        self.assertNotEqual(token, TOKEN_ID1_DEFAULT)
        claims = jwt.decode(token, 'rotated-key', algorithms=['HS256'],
                            options={'verify_exp': False})
        self.assertEqual(claims, {'reset_password': 1, 'exp': 1700000600.0})

    def test_no_database_side_effects(self):
        self.token()
        self.assertEqual(len(db.session.new), 0)
        self.assertEqual(len(db.session.dirty), 0)
        self.assertEqual(len(db.session.deleted), 0)

    # --- quirks -------------------------------------------------------------

    def test_unsaved_user_gets_token_with_null_id(self):
        # Current behaviour that looks like a bug: a user with no id
        # (not flushed) still gets a valid signed token with
        # "reset_password": null instead of an error.
        token = self.token(user=User(username='x', email='x@example.com'))
        self.assertEqual(token, TOKEN_UNSAVED_DEFAULT)
        _, payload, _ = split_token(token)
        self.assertEqual(payload,
                         b'{"reset_password":null,"exp":1700000600.0}')

    def test_negative_expires_in_returns_already_expired_token(self):
        # Current behaviour that looks like a bug: negative or zero
        # expires_in is accepted and yields a token that is already expired.
        token = self.token(expires_in=-10)
        _, payload, _ = split_token(token)
        self.assertEqual(payload, b'{"reset_password":1,"exp":1699999990.0}')
        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(self.user.get_reset_password_token(-10), SECRET,
                       algorithms=['HS256'])

    def test_zero_expires_in(self):
        _, payload, _ = split_token(self.token(expires_in=0))
        self.assertEqual(payload, b'{"reset_password":1,"exp":1700000000.0}')

    def test_empty_secret_key_still_signs(self):
        # Current behaviour that looks like a bug: an empty SECRET_KEY is
        # accepted and a token is produced (signed with an empty key).
        self.app.config['SECRET_KEY'] = ''
        token = self.token()
        claims = jwt.decode(token, '', algorithms=['HS256'],
                            options={'verify_exp': False})
        self.assertEqual(claims, {'reset_password': 1, 'exp': 1700000600.0})

    # --- error paths ------------------------------------------------------

    def test_string_expires_in_raises_type_error(self):
        with mock.patch('app.models.time', return_value=FIXED_NOW), \
                self.assertRaises(TypeError) as cm:
            self.user.get_reset_password_token('10')
        self.assertEqual(str(cm.exception),
                         "unsupported operand type(s) for +: 'float' and "
                         "'str'")

    def test_none_expires_in_raises_type_error(self):
        with mock.patch('app.models.time', return_value=FIXED_NOW), \
                self.assertRaises(TypeError) as cm:
            self.user.get_reset_password_token(None)
        self.assertEqual(str(cm.exception),
                         "unsupported operand type(s) for +: 'float' and "
                         "'NoneType'")

    def test_none_secret_key_raises_type_error(self):
        self.app.config['SECRET_KEY'] = None
        with mock.patch('app.models.time', return_value=FIXED_NOW), \
                self.assertRaises(TypeError) as cm:
            self.user.get_reset_password_token()
        self.assertEqual(str(cm.exception), 'Expected a string value')

    def test_missing_secret_key_raises_key_error(self):
        del self.app.config['SECRET_KEY']
        with mock.patch('app.models.time', return_value=FIXED_NOW), \
                self.assertRaises(KeyError) as cm:
            self.user.get_reset_password_token()
        self.assertEqual(cm.exception.args, ('SECRET_KEY',))

    def test_outside_app_context_raises_runtime_error(self):
        user = User(id=5, username='ctx', email='ctx@example.com')
        self.app_context.pop()
        try:
            with mock.patch('app.models.time', return_value=FIXED_NOW), \
                    self.assertRaises(RuntimeError) as cm:
                user.get_reset_password_token()
            self.assertIn('Working outside of application context',
                          str(cm.exception))
        finally:
            self.app_context.push()


if __name__ == '__main__':
    unittest.main(verbosity=2)
