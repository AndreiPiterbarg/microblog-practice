#!/usr/bin/env python
"""Golden (characterization) tests for U07:
app/models.py User.verify_reset_password_token (staticmethod).

These pin the CURRENT behaviour (PyJWT 2.8.0, SQLAlchemy 2.0.23), including
quirks that look like bugs. They must pass identically before and after the
pyjwt upgrade.
"""
from time import time
import unittest
from unittest import mock
import warnings

import jwt
import sqlalchemy as sa
from app import create_app, db
from app.models import User
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


class VerifyResetPasswordTokenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.key = self.app.config['SECRET_KEY']
        self.u1 = User(username='john', email='john@example.com')
        self.u2 = User(username='susan', email='susan@example.com')
        db.session.add_all([self.u1, self.u2])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def encode(self, payload, key=None, algorithm='HS256'):
        return jwt.encode(payload, self.key if key is None else key,
                          algorithm=algorithm)

    def verify(self, token):
        return User.verify_reset_password_token(token)

    # --- normal cases -----------------------------------------------------

    def test_secret_key_used_is_default(self):
        self.assertEqual(self.key, 'you-will-never-guess')

    def test_round_trip_with_get_reset_password_token(self):
        token = self.u1.get_reset_password_token()
        self.assertIsInstance(token, str)
        self.assertIs(self.verify(token), self.u1)
        self.assertIs(self.verify(self.u2.get_reset_password_token()),
                      self.u2)

    def test_returns_identity_mapped_user_instance(self):
        user = self.verify(self.encode({'reset_password': self.u1.id,
                                        'exp': time() + 600}))
        self.assertIsInstance(user, User)
        self.assertIs(user, self.u1)
        self.assertEqual(user.id, 1)
        self.assertEqual(user.username, 'john')

    def test_callable_via_instance(self):
        token = self.u2.get_reset_password_token()
        self.assertIs(self.u1.verify_reset_password_token(token), self.u2)

    def test_bytes_token_accepted(self):
        token = self.encode({'reset_password': 1}).encode()
        self.assertIs(self.verify(token), self.u1)

    def test_extra_claims_ignored(self):
        token = self.encode({'reset_password': 1, 'exp': time() + 600,
                             'iss': 'someone', 'foo': 'bar',
                             'iat': time() - 10})
        self.assertIs(self.verify(token), self.u1)

    def test_custom_expires_in_still_valid(self):
        token = self.u1.get_reset_password_token(expires_in=3600)
        self.assertIs(self.verify(token), self.u1)

    # --- quirks (current behaviour that looks like a bug) ------------------

    def test_token_without_exp_is_accepted(self):
        # Current behaviour that looks like a bug: 'exp' is not required,
        # so a token with no expiry never expires.
        self.assertIs(self.verify(self.encode({'reset_password': 1})),
                      self.u1)

    def test_token_is_reusable_after_password_change(self):
        # Current behaviour that looks like a bug: tokens are not single-use
        # and are not invalidated when the password changes.
        token = self.u1.get_reset_password_token()
        self.assertIs(self.verify(token), self.u1)
        self.u1.set_password('new-password')
        db.session.commit()
        self.assertIs(self.verify(token), self.u1)
        self.assertIs(self.verify(token), self.u1)

    def test_string_numeric_id_is_accepted(self):
        # Current behaviour that looks like a bug: a string id is coerced
        # by SQLite and still loads the user.
        self.assertIs(self.verify(self.encode({'reset_password': '1'})),
                      self.u1)
        self.assertIs(self.verify(self.encode({'reset_password': '2'})),
                      self.u2)

    def test_float_and_bool_ids_are_accepted(self):
        # Current behaviour that looks like a bug: 1.0 and True load user 1.
        self.assertIs(self.verify(self.encode({'reset_password': 1.0})),
                      self.u1)
        self.assertIs(self.verify(self.encode({'reset_password': True})),
                      self.u1)

    def test_list_and_dict_ids_are_accepted(self):
        # Current behaviour that looks like a bug: the claim is passed
        # straight to session.get(), which treats a 1-element list as a
        # primary-key tuple and a dict as a {pk_name: value} mapping.
        self.assertIs(self.verify(self.encode({'reset_password': [2]})),
                      self.u2)
        self.assertIs(self.verify(self.encode({'reset_password': {'id': 2}})),
                      self.u2)

    def test_bad_shaped_id_raises_instead_of_returning_none(self):
        # Current behaviour that looks like a bug: session.get() is outside
        # the try block, so a validly signed token with a malformed id raises
        # instead of returning None.
        with self.assertRaises(sa.exc.InvalidRequestError) as cm:
            self.verify(self.encode({'reset_password': [1, 2]}))
        self.assertIn('Incorrect number of values in identifier',
                      str(cm.exception))
        with self.assertRaises(sa.exc.InvalidRequestError) as cm:
            self.verify(self.encode({'reset_password': {'x': 1}}))
        self.assertIn('Incorrect names of values in identifier',
                      str(cm.exception))

    def test_null_id_returns_none_with_sawarning(self):
        # Current behaviour that looks like a bug: a null id reaches
        # session.get() and only emits an SAWarning.
        token = self.encode({'reset_password': None})
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            self.assertIsNone(self.verify(token))
        self.assertEqual(
            [(x.category, str(x.message)) for x in w],
            [(sa.exc.SAWarning,
              'fully NULL primary key identity cannot load any object.  '
              'This condition may raise an error in a future release.')])

    def test_no_app_context_returns_none(self):
        # Current behaviour that looks like a bug: the RuntimeError from
        # current_app outside an app context is swallowed by the bare
        # `except Exception`, so a valid token silently returns None.
        token = self.u1.get_reset_password_token()
        self.app_context.pop()
        try:
            self.assertIsNone(self.verify(token))
        finally:
            self.app_context.push()

    # --- rejected tokens return None ---------------------------------------

    def test_unknown_user_id_returns_none(self):
        self.assertIsNone(self.verify(self.encode({'reset_password': 99})))
        self.assertIsNone(self.verify(self.encode({'reset_password': 0})))
        self.assertIsNone(self.verify(self.encode({'reset_password': -1})))
        self.assertIsNone(self.verify(self.encode({'reset_password': 'abc'})))
        self.assertIsNone(self.verify(self.encode({'reset_password': 1.5})))

    def test_deleted_user_returns_none(self):
        token = self.u1.get_reset_password_token()
        db.session.execute(sa.delete(User).where(User.id == 1))
        db.session.commit()
        db.session.expunge_all()
        self.assertIsNone(self.verify(token))

    def test_expired_token_returns_none(self):
        self.assertIsNone(self.verify(
            self.u1.get_reset_password_token(expires_in=-1)))
        self.assertIsNone(self.verify(
            self.encode({'reset_password': 1, 'exp': time() - 1})))
        self.assertIsNone(self.verify(
            self.encode({'reset_password': 1, 'exp': 0})))

    def test_invalid_exp_returns_none(self):
        self.assertIsNone(self.verify(
            self.encode({'reset_password': 1, 'exp': 'soon'})))

    def test_future_nbf_and_iat_return_none(self):
        self.assertIsNone(self.verify(
            self.encode({'reset_password': 1, 'nbf': time() + 100})))
        self.assertIsNone(self.verify(
            self.encode({'reset_password': 1, 'iat': time() + 100})))

    def test_aud_claim_returns_none(self):
        self.assertIsNone(self.verify(
            self.encode({'reset_password': 1, 'aud': 'x'})))

    def test_missing_reset_password_claim_returns_none(self):
        self.assertIsNone(self.verify(self.encode({'exp': time() + 600})))
        self.assertIsNone(self.verify(self.encode({'id': 1})))

    def test_wrong_secret_returns_none(self):
        self.assertIsNone(self.verify(
            self.encode({'reset_password': 1}, key='other-secret')))

    def test_secret_key_read_at_call_time(self):
        token = self.u1.get_reset_password_token()
        self.app.config['SECRET_KEY'] = 'rotated'
        self.assertIsNone(self.verify(token))
        self.app.config['SECRET_KEY'] = 'you-will-never-guess'
        self.assertIs(self.verify(token), self.u1)

    def test_other_algorithms_return_none(self):
        for alg in ('HS384', 'HS512'):
            with self.subTest(alg=alg):
                self.assertIsNone(self.verify(
                    self.encode({'reset_password': 1}, algorithm=alg)))

    def test_alg_none_token_returns_none(self):
        token = jwt.encode({'reset_password': 1}, None, algorithm='none')
        self.assertTrue(token.endswith('.'))
        self.assertIsNone(self.verify(token))

    def test_tampered_tokens_return_none(self):
        token = self.u1.get_reset_password_token()
        for bad in (' ' + token, token + ' ', token + '\n', token + 'x',
                    token[:-1]):
            with self.subTest(bad=bad):
                self.assertIsNone(self.verify(bad))

    def test_garbage_tokens_return_none(self):
        for bad in (None, '', 'garbage', 'a.b.c', 123, b''):
            with self.subTest(bad=bad):
                self.assertIsNone(self.verify(bad))

    # --- boundary: exact calls into jwt / db ------------------------------

    def test_jwt_decode_called_with_exact_arguments(self):
        with mock.patch('app.models.jwt.decode',
                        return_value={'reset_password': 2}) as decode:
            self.assertIs(self.verify('tok'), self.u2)
        decode.assert_called_once_with('tok', 'you-will-never-guess',
                                       algorithms=['HS256'])

    def test_session_get_called_with_user_and_claim(self):
        sentinel = object()
        with mock.patch('app.models.jwt.decode',
                        return_value={'reset_password': 'claim'}), \
                mock.patch.object(db.session, 'get',
                                  return_value=sentinel) as get:
            self.assertIs(self.verify('tok'), sentinel)
        get.assert_called_once_with(User, 'claim')

    def test_any_exception_from_decode_returns_none(self):
        for exc in (RuntimeError('x'), ValueError('x'), KeyError('x'),
                    jwt.InvalidTokenError('x')):
            with self.subTest(exc=type(exc).__name__):
                with mock.patch('app.models.jwt.decode', side_effect=exc), \
                        mock.patch.object(db.session, 'get') as get:
                    self.assertIsNone(self.verify('tok'))
                get.assert_not_called()

    def test_base_exception_from_decode_propagates(self):
        with mock.patch('app.models.jwt.decode',
                        side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.verify('tok')

    def test_exception_from_session_get_propagates(self):
        with mock.patch('app.models.jwt.decode',
                        return_value={'reset_password': 1}), \
                mock.patch.object(db.session, 'get',
                                  side_effect=RuntimeError('db down')):
            with self.assertRaises(RuntimeError) as cm:
                self.verify('tok')
        self.assertEqual(str(cm.exception), 'db down')

    def test_no_db_writes(self):
        self.verify(self.u1.get_reset_password_token())
        self.verify('garbage')
        self.assertFalse(db.session.new)
        self.assertFalse(db.session.dirty)
        self.assertFalse(db.session.deleted)
        self.assertEqual(db.session.scalar(
            sa.select(sa.func.count()).select_from(User)), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
