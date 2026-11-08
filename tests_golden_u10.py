#!/usr/bin/env python
"""Golden (characterization) tests for U10: app/api/auth.py basic_auth.

Covers the HTTPBasicAuth instance, verify_password and basic_auth_error,
exercised through POST /api/tokens. These pin the CURRENT behaviour
(Flask-HTTPAuth 4.8.0, Werkzeug 3.0.1); they are not a specification.
"""
import base64
import unittest
from datetime import datetime, timezone, timedelta
from unittest import mock

from flask import Response
from flask_httpauth import HTTPBasicAuth

from app import create_app, db
from app.api import auth as api_auth
from app.api.auth import basic_auth, verify_password, basic_auth_error
from app.models import User
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


FIXED_TOKEN = '0123456789abcdef0123456789abcdef'
WWW_AUTH = 'Basic realm="Authentication Required"'
UNAUTHORIZED = {'error': 'Unauthorized'}


def basic(username, password, scheme='Basic', encoding='utf-8'):
    raw = f'{username}:{password}'.encode(encoding)
    return {'Authorization': f'{scheme} ' + base64.b64encode(raw).decode()}


class BasicAuthGoldenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()
        self.susan = User(username='susan', email='susan@example.com')
        self.susan.set_password('cat')
        db.session.add(self.susan)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def post_tokens(self, headers=None):
        with mock.patch('app.models.secrets.token_hex',
                        return_value=FIXED_TOKEN) as token_hex:
            rv = self.client.post('/api/tokens', headers=headers or {})
        return rv, token_hex

    def assert_unauthorized(self, rv):
        self.assertEqual(rv.status_code, 401)
        self.assertEqual(rv.get_json(), UNAUTHORIZED)
        self.assertEqual(rv.headers['WWW-Authenticate'], WWW_AUTH)
        self.assertEqual(rv.mimetype, 'application/json')

    def spy_verify(self):
        return mock.patch.object(basic_auth, 'verify_password_callback',
                                 mock.Mock(wraps=verify_password))

    # --- HTTPBasicAuth instance configuration --------------------------

    def test_instance_configuration(self):
        self.assertIsInstance(basic_auth, HTTPBasicAuth)
        self.assertEqual(basic_auth.scheme, 'Basic')
        self.assertEqual(basic_auth.realm, 'Authentication Required')
        self.assertIsNone(basic_auth.header)
        self.assertIs(basic_auth.verify_password_callback, verify_password)
        self.assertIsNone(basic_auth.hash_password_callback)
        self.assertIsNone(basic_auth.get_user_roles_callback)
        # error_handler stores (and the module name binds) the
        # Flask-HTTPAuth wrapper, which wraps the original function.
        self.assertIs(basic_auth.auth_error_callback, basic_auth_error)
        self.assertIs(api_auth.basic_auth_error, basic_auth_error)
        self.assertEqual(basic_auth_error.__name__, 'basic_auth_error')
        self.assertEqual(basic_auth.authenticate_header(), WWW_AUTH)

    # --- verify_password called directly -------------------------------

    def test_verify_password_correct_returns_user_instance(self):
        self.assertIs(verify_password('susan', 'cat'), self.susan)

    def test_verify_password_wrong_password_returns_none(self):
        self.assertIsNone(verify_password('susan', 'dog'))

    def test_verify_password_unknown_user_returns_none(self):
        self.assertIsNone(verify_password('nobody', 'cat'))

    def test_verify_password_empty_credentials_returns_none(self):
        self.assertIsNone(verify_password('', ''))

    def test_verify_password_username_is_case_sensitive_and_not_stripped(self):
        self.assertIsNone(verify_password('Susan', 'cat'))
        self.assertIsNone(verify_password('susan ', 'cat'))
        self.assertIsNone(verify_password('susan', 'cat '))

    def test_verify_password_user_without_password_hash_raises(self):
        # Current behaviour that looks like a bug: a user with no password
        # set makes check_password_hash(None, ...) raise instead of failing
        # authentication cleanly.
        db.session.add(User(username='nopass', email='nopass@example.com'))
        db.session.commit()
        with self.assertRaises(AttributeError):
            verify_password('nopass', 'anything')

    def test_verify_password_accepts_precomputed_werkzeug_hashes(self):
        pbkdf2 = User(username='pb', email='pb@example.com', password_hash=(
            'pbkdf2:sha256:1000$rYv9M1Rm$b32c6f7e4d416a4feb83b4059c0ee91b'
            '10e4d555c1bfbfe79ca6501070d2e013'))
        scrypt = User(username='sc', email='sc@example.com', password_hash=(
            'scrypt:1024:8:1$jSFa5gZ4$81abbb882ce6d8ce06cae1ab0e649c381693'
            '137b5a1244f88108f3b7db6748b2313d6d39a1044e88602ea1463bec6a327d'
            '393f2a2f6a634335475c17baebe6df'))
        db.session.add_all([pbkdf2, scrypt])
        db.session.commit()
        self.assertIs(verify_password('pb', 'cat'), pbkdf2)
        self.assertIsNone(verify_password('pb', 'dog'))
        self.assertIs(verify_password('sc', 'cat'), scrypt)
        self.assertIsNone(verify_password('sc', 'dog'))

    def test_set_password_default_hash_method(self):
        self.assertTrue(self.susan.password_hash.startswith(
            'scrypt:32768:8:1$'))

    # --- basic_auth_error called directly ------------------------------

    def test_basic_auth_error_401(self):
        with self.app.test_request_context():
            rv = basic_auth_error(401)
        self.assertIsInstance(rv, Response)
        self.assertEqual(rv.status_code, 401)
        self.assertEqual(rv.get_json(), UNAUTHORIZED)
        self.assertEqual(rv.headers['WWW-Authenticate'], WWW_AUTH)

    def test_basic_auth_error_403(self):
        with self.app.test_request_context():
            rv = basic_auth_error(403)
        self.assertEqual(rv.status_code, 403)
        self.assertEqual(rv.get_json(), {'error': 'Forbidden'})
        self.assertEqual(rv.headers['WWW-Authenticate'], WWW_AUTH)

    def test_basic_auth_error_200_is_not_coerced_to_401(self):
        # Current behaviour that looks like a bug: because error_response
        # returns a tuple, Flask-HTTPAuth's "use 401 if status is 200"
        # fallback is skipped and a 200 "error" is returned.
        with self.app.test_request_context():
            rv = basic_auth_error(200)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.get_json(), {'error': 'OK'})
        self.assertEqual(rv.headers['WWW-Authenticate'], WWW_AUTH)

    def test_basic_auth_error_unknown_status(self):
        with self.app.test_request_context():
            rv = basic_auth_error(499)
        self.assertEqual(rv.status_code, 499)
        self.assertEqual(rv.get_json(), {'error': 'Unknown error'})
        self.assertEqual(rv.headers['WWW-Authenticate'], WWW_AUTH)

    def test_basic_auth_error_calls_error_response_with_status_only(self):
        with mock.patch.object(api_auth, 'error_response',
                               return_value=({'x': 1}, 418)) as er:
            with self.app.test_request_context():
                rv = basic_auth_error(401)
        er.assert_called_once_with(401)
        self.assertEqual(rv.status_code, 418)
        self.assertEqual(rv.get_json(), {'x': 1})

    # --- POST /api/tokens: success ------------------------------------

    def test_post_tokens_success(self):
        before = datetime.now(timezone.utc)
        with self.spy_verify() as spy:
            rv, token_hex = self.post_tokens(basic('susan', 'cat'))
        spy.assert_called_once_with('susan', 'cat')
        token_hex.assert_called_once_with(16)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.get_json(), {'token': FIXED_TOKEN})
        self.assertEqual(rv.mimetype, 'application/json')
        self.assertNotIn('WWW-Authenticate', rv.headers)
        db.session.expire_all()
        user = db.session.get(User, self.susan.id)
        self.assertEqual(user.token, FIXED_TOKEN)
        exp = user.token_expiration.replace(tzinfo=timezone.utc)
        self.assertGreaterEqual(exp, before + timedelta(seconds=3600))
        self.assertLessEqual(
            exp, datetime.now(timezone.utc) + timedelta(seconds=3600))

    def test_post_tokens_twice_returns_same_token(self):
        rv1, _ = self.post_tokens(basic('susan', 'cat'))
        with mock.patch('app.models.secrets.token_hex',
                        return_value='f' * 32) as token_hex:
            rv2 = self.client.post('/api/tokens',
                                   headers=basic('susan', 'cat'))
        token_hex.assert_not_called()
        self.assertEqual(rv1.get_json(), {'token': FIXED_TOKEN})
        self.assertEqual(rv2.get_json(), {'token': FIXED_TOKEN})

    def test_post_tokens_scheme_is_case_insensitive(self):
        rv, _ = self.post_tokens(basic('susan', 'cat', scheme='basic'))
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.get_json(), {'token': FIXED_TOKEN})

    def test_post_tokens_any_scheme_is_accepted(self):
        # Current behaviour that looks like a bug: HTTPBasicAuth.get_auth
        # never checks the scheme, so "Bearer <base64 user:pass>" (or any
        # other word) authenticates just like "Basic".
        for scheme in ('Bearer', 'Token', 'Digest', 'xyz'):
            with self.subTest(scheme=scheme):
                with self.spy_verify() as spy:
                    rv, _ = self.post_tokens(
                        basic('susan', 'cat', scheme=scheme))
                spy.assert_called_once_with('susan', 'cat')
                self.assertEqual(rv.status_code, 200)
                self.assertEqual(rv.get_json(), {'token': FIXED_TOKEN})

    def test_post_tokens_password_with_colon(self):
        u = User(username='colon', email='colon@example.com')
        u.set_password('a:b:c')
        db.session.add(u)
        db.session.commit()
        with self.spy_verify() as spy:
            rv, _ = self.post_tokens(basic('colon', 'a:b:c'))
        spy.assert_called_once_with('colon', 'a:b:c')
        self.assertEqual(rv.status_code, 200)

    def test_post_tokens_utf8_and_latin1_credentials(self):
        u = User(username='j\u00f6hn', email='john@example.com')
        u.set_password('p\u00e4ss')
        db.session.add(u)
        db.session.commit()
        for encoding in ('utf-8', 'latin-1'):
            with self.subTest(encoding=encoding):
                with self.spy_verify() as spy:
                    rv, _ = self.post_tokens(basic(
                        'j\u00f6hn', 'p\u00e4ss', encoding=encoding))
                spy.assert_called_once_with('j\u00f6hn', 'p\u00e4ss')
                self.assertEqual(rv.status_code, 200)

    def test_post_tokens_extra_space_before_credentials_is_tolerated(self):
        creds = base64.b64encode(b'susan:cat').decode()
        rv, _ = self.post_tokens({'Authorization': f'Basic  {creds}'})
        self.assertEqual(rv.status_code, 200)

    def test_post_tokens_missing_base64_padding_is_rejected(self):
        creds = base64.b64encode(b'susan:ca').decode()  # ends with '='
        self.assertTrue(creds.endswith('='))
        with self.spy_verify() as spy:
            rv, _ = self.post_tokens(
                {'Authorization': 'Basic ' + creds.rstrip('=')})
        spy.assert_called_once_with('', '')
        self.assert_unauthorized(rv)

    # --- POST /api/tokens: failures -----------------------------------

    def test_post_tokens_wrong_password(self):
        with self.spy_verify() as spy:
            rv, token_hex = self.post_tokens(basic('susan', 'dog'))
        spy.assert_called_once_with('susan', 'dog')
        token_hex.assert_not_called()
        self.assert_unauthorized(rv)
        db.session.expire_all()
        self.assertIsNone(db.session.get(User, self.susan.id).token)

    def test_post_tokens_unknown_user(self):
        with self.spy_verify() as spy:
            rv, _ = self.post_tokens(basic('nobody', 'cat'))
        spy.assert_called_once_with('nobody', 'cat')
        self.assert_unauthorized(rv)

    def test_post_tokens_wrong_case_username(self):
        rv, _ = self.post_tokens(basic('SUSAN', 'cat'))
        self.assert_unauthorized(rv)

    def test_post_tokens_no_authorization_header(self):
        # verify_password is still invoked, with empty strings.
        with self.spy_verify() as spy:
            rv, _ = self.post_tokens()
        spy.assert_called_once_with('', '')
        self.assert_unauthorized(rv)

    def test_post_tokens_malformed_headers_call_verify_with_empty(self):
        cases = {
            'no space': 'Basic',
            'scheme only with space': 'Basic ',
            'invalid base64': 'Basic !!!notbase64',
            'no colon': 'Basic ' + base64.b64encode(b'susancat').decode(),
            'empty value': '',
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                with self.spy_verify() as spy:
                    rv, _ = self.post_tokens({'Authorization': value})
                spy.assert_called_once_with('', '')
                self.assert_unauthorized(rv)

    def test_post_tokens_empty_username_user_without_credentials(self):
        # Current behaviour that looks like a bug: a request with NO
        # Authorization header is passed to verify_password as ('', ''),
        # so a user whose username and password are both empty strings is
        # authenticated and receives a token without sending credentials.
        u = User(username='', email='empty@example.com')
        u.set_password('')
        db.session.add(u)
        db.session.commit()
        with self.spy_verify() as spy:
            rv, _ = self.post_tokens()
        spy.assert_called_once_with('', '')
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.get_json(), {'token': FIXED_TOKEN})
        db.session.expire_all()
        self.assertEqual(db.session.get(User, u.id).token, FIXED_TOKEN)

    def test_post_tokens_user_without_password_hash_propagates_error(self):
        # Current behaviour that looks like a bug: no clean 401; the
        # AttributeError escapes the view (propagated because TESTING=True).
        db.session.add(User(username='nopass', email='nopass@example.com'))
        db.session.commit()
        with self.assertRaises(AttributeError):
            self.client.post('/api/tokens', headers=basic('nopass', 'x'))

    def test_options_tokens_bypasses_auth(self):
        with self.spy_verify() as spy:
            rv = self.client.options('/api/tokens')
        spy.assert_not_called()
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(set(rv.headers['Allow'].split(', ')),
                         {'POST', 'DELETE', 'OPTIONS'})
        self.assertNotIn('WWW-Authenticate', rv.headers)

    def test_get_tokens_method_not_allowed(self):
        with self.spy_verify() as spy:
            rv = self.client.get('/api/tokens', headers=basic('susan', 'cat'))
        spy.assert_not_called()
        self.assertEqual(rv.status_code, 405)


if __name__ == '__main__':
    unittest.main(verbosity=2)
