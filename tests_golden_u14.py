#!/usr/bin/env python
"""Golden (characterization) tests for app/api/errors.py (unit U14).

These pin down the CURRENT behaviour of error_response, bad_request and
handle_exception, including quirks. They must pass unchanged before and
after any werkzeug/flask upgrade.
"""
import unittest
from unittest import mock

from flask import Response
from werkzeug.exceptions import (HTTPException, BadRequest, Forbidden,
                                 InternalServerError, MethodNotAllowed,
                                 NotFound)

from app import create_app, db
from app.api import errors as api_errors
from app.api.errors import error_response, bad_request, handle_exception
from app.models import User
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


class _AppCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()


class ErrorResponseCase(_AppCase):
    def test_known_codes_without_message(self):
        expected = {
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            418: "I'm a teapot",
            500: 'Internal Server Error',
        }
        for code, phrase in expected.items():
            with self.subTest(code=code):
                rv = error_response(code)
                self.assertIs(type(rv), tuple)
                self.assertEqual(len(rv), 2)
                self.assertIs(type(rv[0]), dict)
                self.assertEqual(rv, ({'error': phrase}, code))

    def test_with_message(self):
        self.assertEqual(error_response(404, 'no such user'),
                         ({'error': 'Not Found', 'message': 'no such user'},
                          404))

    def test_message_keyword(self):
        self.assertEqual(error_response(status_code=500, message='boom'),
                         ({'error': 'Internal Server Error',
                           'message': 'boom'}, 500))

    def test_payload_key_order(self):
        payload, _ = error_response(400, 'x')
        self.assertEqual(list(payload), ['error', 'message'])

    def test_falsy_message_is_omitted(self):
        # Current behaviour that looks like a bug: any falsy message
        # ('' / 0 / [] / {} / False) is silently dropped, not just None.
        for message in (None, '', 0, [], {}, False):
            with self.subTest(message=message):
                self.assertEqual(error_response(404, message),
                                 ({'error': 'Not Found'}, 404))

    def test_non_string_message_passed_through_unchanged(self):
        msg = {'field': ['required']}
        payload, status = error_response(400, msg)
        self.assertIs(payload['message'], msg)
        self.assertEqual(status, 400)
        self.assertEqual(error_response(400, 7),
                         ({'error': 'Bad Request', 'message': 7}, 400))

    def test_unknown_numeric_code(self):
        self.assertEqual(error_response(999), ({'error': 'Unknown error'},
                                               999))
        self.assertEqual(error_response(0), ({'error': 'Unknown error'}, 0))
        self.assertEqual(error_response(999, 'm'),
                         ({'error': 'Unknown error', 'message': 'm'}, 999))

    def test_string_status_code_not_looked_up(self):
        # Current behaviour that looks like a bug: a string code is not
        # converted, so the phrase is 'Unknown error' while the string status
        # is returned unchanged (Flask then serves it as 404 NOT FOUND).
        self.assertEqual(error_response('404'),
                         ({'error': 'Unknown error'}, '404'))
        with self.app.test_request_context('/api/users'):
            r = self.app.make_response(error_response('404'))
        self.assertEqual(r.status, '404 NOT FOUND')
        self.assertEqual(r.get_json(), {'error': 'Unknown error'})

    def test_none_status_code(self):
        # Current behaviour that looks like a bug: None is accepted and
        # returned as the status, which Flask turns into a 200 response.
        self.assertEqual(error_response(None),
                         ({'error': 'Unknown error'}, None))
        with self.app.test_request_context('/api/users'):
            r = self.app.make_response(error_response(None))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {'error': 'Unknown error'})

    def test_float_and_bool_codes(self):
        # Lookup is by dict hashing: 404.0 == 404, True == 1 (not a code).
        self.assertEqual(error_response(404.0), ({'error': 'Not Found'},
                                                 404.0))
        self.assertEqual(error_response(True), ({'error': 'Unknown error'},
                                                True))

    def test_returns_fresh_payload_each_call(self):
        a, _ = error_response(404)
        a['error'] = 'mutated'
        self.assertEqual(error_response(404), ({'error': 'Not Found'}, 404))

    def test_rendered_response(self):
        with self.app.test_request_context('/api/users'):
            r = self.app.make_response(error_response(403, 'nope'))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.content_type, 'application/json')
        self.assertEqual(r.get_data(as_text=True),
                         '{"error":"Forbidden","message":"nope"}\n')


class BadRequestCase(_AppCase):
    def test_bad_request(self):
        self.assertEqual(bad_request('please use a different username'),
                         ({'error': 'Bad Request',
                           'message': 'please use a different username'},
                          400))

    def test_bad_request_delegates_to_error_response(self):
        with mock.patch.object(api_errors, 'error_response',
                               return_value='sentinel') as m:
            self.assertEqual(bad_request('m'), 'sentinel')
        m.assert_called_once_with(400, 'm')

    def test_bad_request_empty_message(self):
        # Current behaviour that looks like a bug: empty message is dropped.
        self.assertEqual(bad_request(''), ({'error': 'Bad Request'}, 400))
        self.assertEqual(bad_request(None), ({'error': 'Bad Request'}, 400))


class HandleExceptionDirectCase(_AppCase):
    def test_registered_on_api_blueprint_only(self):
        spec = self.app.error_handler_spec
        self.assertIs(spec['api'][None][HTTPException], handle_exception)
        self.assertNotIn(HTTPException, spec[None][None])
        self.assertIsNot(spec[None][404][NotFound], handle_exception)
        self.assertIsNot(spec[None][500][InternalServerError],
                         handle_exception)

    def test_maps_exception_code(self):
        cases = [(BadRequest(), ({'error': 'Bad Request'}, 400)),
                 (Forbidden(), ({'error': 'Forbidden'}, 403)),
                 (NotFound(), ({'error': 'Not Found'}, 404))]
        for exc, expected in cases:
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(handle_exception(exc), expected)

    def test_calls_error_response_with_code_only(self):
        with mock.patch.object(api_errors, 'error_response',
                               return_value='sentinel') as m:
            self.assertEqual(handle_exception(NotFound('custom text')),
                             'sentinel')
        m.assert_called_once_with(404)

    def test_description_is_dropped(self):
        # Current behaviour that looks like a bug: the exception description
        # (e.g. abort(404, 'no such user')) never reaches the client.
        self.assertEqual(handle_exception(NotFound('no such user')),
                         ({'error': 'Not Found'}, 404))

    def test_custom_subclass_code(self):
        class Teapot(HTTPException):
            code = 418
        self.assertEqual(handle_exception(Teapot()),
                         ({'error': "I'm a teapot"}, 418))

        class Weird(HTTPException):
            code = 599
        self.assertEqual(handle_exception(Weird()),
                         ({'error': 'Unknown error'}, 599))

    def test_bare_http_exception_becomes_200(self):
        # Current behaviour that looks like a bug: a code-less HTTPException
        # yields status None, which Flask serves as 200 OK.
        self.assertEqual(handle_exception(HTTPException()),
                         ({'error': 'Unknown error'}, None))
        with self.app.test_request_context('/api/users'):
            r = self.app.make_response(handle_exception(HTTPException()))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_data(as_text=True),
                         '{"error":"Unknown error"}\n')

    def test_attached_response_is_ignored(self):
        # Current behaviour that looks like a bug: abort(Response(...)) style
        # exceptions lose their response and become a 200 JSON error.
        exc = HTTPException(response=Response('custom', 202))
        self.assertEqual(handle_exception(exc),
                         ({'error': 'Unknown error'}, None))
        with self.app.test_request_context('/api/users'):
            r = self.app.make_response(handle_exception(exc))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {'error': 'Unknown error'})

    def test_exception_headers_are_dropped(self):
        # Current behaviour that looks like a bug: headers carried by the
        # exception (e.g. Allow on 405) are not copied to the response.
        with self.app.test_request_context('/api/users'):
            r = self.app.make_response(
                handle_exception(MethodNotAllowed(['GET'])))
        self.assertEqual(r.status_code, 405)
        self.assertIsNone(r.headers.get('Allow'))
        self.assertEqual(r.get_json(), {'error': 'Method Not Allowed'})


class HandleExceptionViaApiCase(_AppCase):
    def setUp(self):
        super().setUp()
        self.client = self.app.test_client()
        self.u1 = User(username='john', email='john@example.com')
        self.u2 = User(username='susan', email='susan@example.com')
        db.session.add_all([self.u1, self.u2])
        db.session.commit()
        self.token = self.u1.get_token()
        db.session.commit()
        self.auth = {'Authorization': 'Bearer ' + self.token}

    def test_get_or_404_in_api_view_bypasses_handler(self):
        # Current behaviour that looks like a bug: Flask prefers the app-level
        # 404 handler (app/errors/handlers.py) over this blueprint's
        # HTTPException handler, so handle_exception never sees API 404s and
        # a browser-style Accept header gets an HTML page from the JSON API.
        with mock.patch.object(api_errors, 'error_response',
                               wraps=api_errors.error_response) as m:
            r = self.client.get('/api/users/999', headers=self.auth)
            r_html = self.client.get(
                '/api/users/999',
                headers={**self.auth, 'Accept': 'text/html'})
        m.assert_not_called()
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.content_type, 'application/json')
        self.assertEqual(r.get_data(as_text=True), '{"error":"Not Found"}\n')
        self.assertEqual(r_html.status_code, 404)
        self.assertEqual(r_html.content_type, 'text/html; charset=utf-8')

    def test_abort_403_in_api_view(self):
        with mock.patch.object(api_errors, 'error_response',
                               wraps=api_errors.error_response) as m:
            r = self.client.put(f'/api/users/{self.u2.id}', json={},
                                headers=self.auth)
        m.assert_called_once_with(403)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_data(as_text=True), '{"error":"Forbidden"}\n')

    def test_invalid_json_body_in_api_view(self):
        # request.get_json() raises BadRequest; its description is dropped.
        with mock.patch.object(api_errors, 'error_response',
                               wraps=api_errors.error_response) as m:
            r = self.client.post('/api/users', data='not json',
                                 content_type='application/json')
        m.assert_called_once_with(400)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_data(as_text=True),
                         '{"error":"Bad Request"}\n')

    def test_missing_json_content_type_in_api_view(self):
        r = self.client.post('/api/users', data='x')
        self.assertEqual(r.status_code, 415)
        self.assertEqual(r.get_json(),
                         {'error': 'Unsupported Media Type'})

    def test_bad_request_from_api_view(self):
        r = self.client.post('/api/users', json={'username': 'x'})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json(), {
            'error': 'Bad Request',
            'message': 'must include username, email and password fields'})

    def test_unauthorized_uses_error_response(self):
        r = self.client.get('/api/users')
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.get_data(as_text=True),
                         '{"error":"Unauthorized"}\n')
        self.assertEqual(r.headers['WWW-Authenticate'],
                         'Bearer realm="Authentication Required"')

    def test_405_on_api_route_not_handled(self):
        # Current behaviour that looks like a bug: routing errors under /api
        # bypass the API handler, so 405 is werkzeug's default HTML page.
        with mock.patch.object(api_errors, 'error_response') as m:
            r = self.client.patch('/api/users')
        m.assert_not_called()
        self.assertEqual(r.status_code, 405)
        self.assertEqual(r.content_type, 'text/html; charset=utf-8')
        self.assertIn('<title>405 Method Not Allowed</title>',
                      r.get_data(as_text=True))
        self.assertEqual(sorted(r.headers['Allow'].split(', ')),
                         ['GET', 'HEAD', 'OPTIONS', 'POST'])

    def test_unknown_api_url_not_handled_by_api_handler(self):
        # Unrouted /api URLs go to the app-level 404 handler, not
        # handle_exception; with an HTML Accept header the result is HTML.
        with mock.patch.object(api_errors, 'error_response') as m:
            r = self.client.get('/api/nope', headers={'Accept': 'text/html'})
        m.assert_not_called()
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.content_type, 'text/html; charset=utf-8')


if __name__ == '__main__':
    unittest.main(verbosity=2)
