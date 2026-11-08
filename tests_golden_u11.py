#!/usr/bin/env python
"""Golden (characterization) tests for U11: app/api/auth.py token_auth.

Covers the HTTPTokenAuth instance, verify_token and token_auth_error, as
exercised directly and via DELETE /api/tokens and the token-protected
/api/users routes. These pin CURRENT behaviour, not intended behaviour.
"""
import base64
from datetime import datetime, timezone, timedelta
import unittest
from unittest import mock
from flask import Response
from flask_httpauth import HTTPTokenAuth
from app import create_app, db
from app.models import User
from app.api import auth
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


WWW_AUTH = 'Bearer realm="Authentication Required"'
UNAUTHORIZED = {'error': 'Unauthorized'}
BASIC_JOHN = 'Basic ' + base64.b64encode(b'john:' + b'cat').decode()


class TokenAuthGoldenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()
        self.john = User(username='john', email='john@example.com')
        self.john.set_password('cat')
        self.susan = User(username='susan', email='susan@example.com')
        db.session.add_all([self.john, self.susan])
        db.session.commit()
        self.token = self.john.get_token()
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def bearer(self, token=None):
        return {'Authorization': 'Bearer ' + (token or self.token)}

    def assert_unauthorized(self, rv):
        self.assertEqual(rv.status_code, 401)
        self.assertEqual(rv.get_json(), UNAUTHORIZED)
        self.assertEqual(rv.data, b'{"error":"Unauthorized"}\n')
        self.assertEqual(rv.headers['Content-Type'], 'application/json')
        self.assertEqual(rv.headers['WWW-Authenticate'], WWW_AUTH)


class TokenAuthConfigTests(TokenAuthGoldenCase):
    def test_instance_configuration(self):
        self.assertIsInstance(auth.token_auth, HTTPTokenAuth)
        self.assertEqual(auth.token_auth.scheme, 'Bearer')
        self.assertEqual(auth.token_auth.realm, 'Authentication Required')
        self.assertIsNone(auth.token_auth.header)
        self.assertIs(auth.token_auth.verify_token_callback,
                      auth.verify_token)
        self.assertIs(auth.token_auth.auth_error_callback,
                      auth.token_auth_error)

    def test_authenticate_header(self):
        self.assertEqual(auth.token_auth.authenticate_header(), WWW_AUTH)


class VerifyTokenTests(TokenAuthGoldenCase):
    def test_valid_token_returns_user(self):
        self.assertIs(auth.verify_token(self.token), self.john)

    def test_unknown_token_returns_none(self):
        self.assertIsNone(auth.verify_token('0' * 32))

    def test_token_is_case_sensitive(self):
        self.assertIsNone(auth.verify_token(self.token.upper()))

    def test_falsy_tokens_short_circuit_without_lookup(self):
        with mock.patch('app.models.User.check_token') as check:
            self.assertIsNone(auth.verify_token(''))
            self.assertIsNone(auth.verify_token(None))
            self.assertIsNone(auth.verify_token(0))
        check.assert_not_called()

    def test_truthy_token_delegates_to_check_token(self):
        sentinel = object()
        with mock.patch('app.models.User.check_token',
                        return_value=sentinel) as check:
            self.assertIs(auth.verify_token('abc'), sentinel)
        check.assert_called_once_with('abc')

    def test_expired_token_returns_none(self):
        self.john.token_expiration = datetime.now(timezone.utc) - \
            timedelta(seconds=5)
        db.session.commit()
        self.assertIsNone(auth.verify_token(self.token))

    def test_revoked_token_returns_none(self):
        self.john.revoke_token()
        db.session.commit()
        self.assertIsNone(auth.verify_token(self.token))

    def test_does_not_write_to_db(self):
        before = (self.john.token, self.john.token_expiration)
        auth.verify_token(self.token)
        auth.verify_token('nope')
        self.assertFalse(db.session.dirty)
        self.assertEqual((self.john.token, self.john.token_expiration),
                         before)

    def test_token_with_null_expiration_raises(self):
        # Current behaviour that looks like a bug: a stored token whose
        # token_expiration is NULL makes verify_token (via
        # User.check_token) raise AttributeError instead of returning None.
        self.susan.token = 'abc'
        db.session.commit()
        with self.assertRaises(AttributeError) as cm:
            auth.verify_token('abc')
        self.assertEqual(str(cm.exception),
                         "'NoneType' object has no attribute 'replace'")


class TokenAuthErrorTests(TokenAuthGoldenCase):
    def test_401(self):
        with self.app.test_request_context():
            rv = auth.token_auth_error(401)
        self.assertIsInstance(rv, Response)
        self.assertEqual(rv.status_code, 401)
        self.assertEqual(rv.get_json(), UNAUTHORIZED)
        self.assertEqual(rv.headers['WWW-Authenticate'], WWW_AUTH)
        self.assertEqual(rv.headers['Content-Type'], 'application/json')

    def test_403_keeps_status_and_adds_www_authenticate(self):
        with self.app.test_request_context():
            rv = auth.token_auth_error(403)
        self.assertEqual(rv.status_code, 403)
        self.assertEqual(rv.get_json(), {'error': 'Forbidden'})
        self.assertEqual(rv.headers['WWW-Authenticate'], WWW_AUTH)

    def test_unknown_status(self):
        with self.app.test_request_context():
            rv = auth.token_auth_error(999)
        self.assertEqual(rv.status_code, 999)
        self.assertEqual(rv.get_json(), {'error': 'Unknown error'})
        self.assertEqual(rv.headers['WWW-Authenticate'], WWW_AUTH)


class AuthorizationHeaderTests(TokenAuthGoldenCase):
    def test_no_header(self):
        self.assert_unauthorized(self.client.get('/api/users/1'))

    def test_valid_bearer(self):
        rv = self.client.get('/api/users/1', headers=self.bearer())
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.get_json()['username'], 'john')

    def test_scheme_is_case_insensitive(self):
        for scheme in ('bearer', 'BEARER', 'BeArEr'):
            rv = self.client.get(
                '/api/users/1',
                headers={'Authorization': scheme + ' ' + self.token})
            self.assertEqual(rv.status_code, 200, scheme)

    def test_extra_whitespace_around_token_is_stripped(self):
        for value in ('Bearer  ' + self.token, 'Bearer ' + self.token + ' '):
            rv = self.client.get('/api/users/1',
                                 headers={'Authorization': value})
            self.assertEqual(rv.status_code, 200, repr(value))

    def test_rejected_headers(self):
        for value in ('', 'Bearer', 'Bearer ', self.token,
                      'Token ' + self.token, BASIC_JOHN,
                      'Bearer ' + self.token + ' x',
                      'Bearer ' + self.token.upper()):
            rv = self.client.get('/api/users/1',
                                 headers={'Authorization': value})
            self.assert_unauthorized(rv)

    def test_token_in_query_string_is_ignored(self):
        self.assert_unauthorized(
            self.client.get('/api/users/1?token=' + self.token))

    def test_token_passed_to_check_token(self):
        cases = [
            ('Bearer abc', 'abc'),
            ('bearer abc', 'abc'),
            ('Bearer  abc', 'abc'),
            ('Bearer abc ', 'abc'),
            ('Bearer "abc"', '"abc"'),
            ('Bearer abc=', 'abc='),
            ('Bearer a,b', 'a,b'),
        ]
        with mock.patch('app.models.User.check_token',
                        return_value=None) as check:
            for value, expected in cases:
                check.reset_mock()
                rv = self.client.delete('/api/tokens',
                                        headers={'Authorization': value})
                self.assert_unauthorized(rv)
                check.assert_called_once_with(expected)

    def test_check_token_not_called_without_token(self):
        with mock.patch('app.models.User.check_token') as check:
            for value in (None, 'Bearer', 'Bearer ', 'Basic xyz'):
                headers = {'Authorization': value} if value else None
                rv = self.client.delete('/api/tokens', headers=headers)
                self.assert_unauthorized(rv)
        check.assert_not_called()

    def test_expired_token_rejected(self):
        self.john.token_expiration = datetime.now(timezone.utc) - \
            timedelta(seconds=5)
        db.session.commit()
        self.assert_unauthorized(
            self.client.get('/api/users/1', headers=self.bearer()))

    def test_null_expiration_token_propagates_exception(self):
        # Current behaviour that looks like a bug: a token row with NULL
        # token_expiration raises instead of returning 401 (500 outside
        # TESTING).
        self.susan.token = 'abc'
        db.session.commit()
        with self.assertRaises(AttributeError):
            self.client.get('/api/users/1', headers=self.bearer('abc'))


class RevokeTokenTests(TokenAuthGoldenCase):
    def test_revoke_requires_token(self):
        self.assert_unauthorized(self.client.delete('/api/tokens'))
        self.assertIs(auth.verify_token(self.token), self.john)

    def test_revoke_with_basic_auth_rejected(self):
        self.assert_unauthorized(self.client.delete(
            '/api/tokens', headers={'Authorization': BASIC_JOHN}))

    def test_revoke_success(self):
        before = datetime.now(timezone.utc)
        rv = self.client.delete('/api/tokens', headers=self.bearer())
        self.assertEqual(rv.status_code, 204)
        self.assertEqual(rv.data, b'')
        # Current behaviour that looks like a bug: the empty 204 response
        # is labelled 'text/html; charset=utf-8'.
        self.assertEqual(rv.headers['Content-Type'],
                         'text/html; charset=utf-8')
        self.assertNotIn('WWW-Authenticate', rv.headers)
        db.session.expire_all()
        john = db.session.get(User, self.john.id)
        # Current behaviour that looks like a bug: the revoked token value
        # is kept in the DB; only its expiration is moved into the past.
        self.assertEqual(john.token, self.token)
        expiration = john.token_expiration.replace(tzinfo=timezone.utc)
        self.assertLess(expiration, datetime.now(timezone.utc))
        self.assertGreaterEqual(expiration,
                                before - timedelta(seconds=2))
        self.assertIsNone(auth.verify_token(self.token))

    def test_revoked_token_cannot_be_reused(self):
        self.assertEqual(self.client.delete(
            '/api/tokens', headers=self.bearer()).status_code, 204)
        self.assert_unauthorized(
            self.client.delete('/api/tokens', headers=self.bearer()))
        self.assert_unauthorized(
            self.client.get('/api/users/1', headers=self.bearer()))

    def test_revoke_only_affects_token_owner(self):
        susan_token = self.susan.get_token()
        db.session.commit()
        self.client.delete('/api/tokens', headers=self.bearer())
        self.assertIs(auth.verify_token(susan_token), self.susan)
        self.assertEqual(self.client.get(
            '/api/users/1', headers=self.bearer(susan_token)).status_code,
            200)

    def test_options_bypasses_auth(self):
        # Current behaviour: Flask answers OPTIONS automatically, so
        # token_auth is never consulted.
        with mock.patch('app.models.User.check_token') as check:
            rv = self.client.open('/api/tokens', method='OPTIONS')
        check.assert_not_called()
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.data, b'')
        self.assertEqual(set(rv.headers['Allow'].split(', ')),
                         {'DELETE', 'POST', 'OPTIONS'})


class ProtectedUserRoutesTests(TokenAuthGoldenCase):
    PROTECTED = [
        ('GET', '/api/users/1'),
        ('GET', '/api/users'),
        ('GET', '/api/users/1/followers'),
        ('GET', '/api/users/1/following'),
        ('PUT', '/api/users/1'),
    ]

    def test_all_protected_routes_require_token(self):
        for method, url in self.PROTECTED:
            rv = self.client.open(url, method=method, json={})
            self.assert_unauthorized(rv)

    def test_all_protected_routes_reject_bad_token(self):
        for method, url in self.PROTECTED:
            rv = self.client.open(url, method=method, json={},
                                  headers=self.bearer('bad'))
            self.assert_unauthorized(rv)

    def test_auth_checked_before_404(self):
        self.assert_unauthorized(self.client.get('/api/users/99'))
        rv = self.client.get('/api/users/99', headers=self.bearer())
        self.assertEqual(rv.status_code, 404)
        self.assertEqual(rv.get_json(), {'error': 'Not Found'})
        self.assertNotIn('WWW-Authenticate', rv.headers)

    def test_get_user_with_token(self):
        rv = self.client.get('/api/users/2', headers=self.bearer())
        self.assertEqual(rv.status_code, 200)
        data = rv.get_json()
        self.assertEqual(data['id'], 2)
        self.assertEqual(data['username'], 'susan')
        self.assertNotIn('email', data)

    def test_collections_with_token(self):
        rv = self.client.get('/api/users', headers=self.bearer())
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.get_json()['_meta']['total_items'], 2)
        for url in ('/api/users/1/followers', '/api/users/1/following'):
            rv = self.client.get(url, headers=self.bearer())
            self.assertEqual(rv.status_code, 200, url)
            self.assertEqual(rv.get_json()['items'], [])

    def test_put_current_user_is_token_owner(self):
        rv = self.client.put('/api/users/1', headers=self.bearer(),
                             json={'about_me': 'hi'})
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.get_json()['about_me'], 'hi')

    def test_put_other_user_forbidden(self):
        rv = self.client.put('/api/users/2', headers=self.bearer(),
                             json={'about_me': 'hi'})
        self.assertEqual(rv.status_code, 403)
        self.assertEqual(rv.get_json(), {'error': 'Forbidden'})
        self.assertNotIn('WWW-Authenticate', rv.headers)
        db.session.expire_all()
        self.assertIsNone(db.session.get(User, 2).about_me)

    def test_create_user_not_protected(self):
        rv = self.client.post('/api/users', json={
            'username': 'bob', 'email': 'bob@example.com',
            'password': 'pw'})
        self.assertEqual(rv.status_code, 201)

    def test_successful_auth_does_not_modify_token(self):
        before = (self.john.token, self.john.token_expiration)
        self.client.get('/api/users/1', headers=self.bearer())
        db.session.expire_all()
        john = db.session.get(User, 1)
        self.assertEqual((john.token, john.token_expiration), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
