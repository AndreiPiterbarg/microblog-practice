#!/usr/bin/env python
"""Golden (characterization) tests for app/translate.py:translate (U05).

These pin the CURRENT behaviour of translate(), including quirks, so that a
later security fix (e.g. adding a timeout to requests.post, upgrading
requests/urllib3/idna/certifi) can be checked for zero behaviour change.
requests.post is always mocked; no network access is made.
"""
import glob
import os
import unittest
from unittest import mock

import requests

from app import create_app, db
from app.translate import translate
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None
    MS_TRANSLATOR_KEY = None


NOT_CONFIGURED = 'Error: the translation service is not configured.'
FAILED = 'Error: the translation service failed.'
BASE_URL = ('https://api.cognitive.microsofttranslator.com'
            '/translate?api-version=3.0')


def make_response(status_code=200, payload=None):
    r = mock.Mock(name='Response')
    r.status_code = status_code
    r.json.return_value = payload
    return r


def ok_payload(*texts):
    return [{'translations': [{'text': t, 'to': 'es'} for t in texts]}]


class TranslateCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        # translate() runs inside a request (the /translate route); its
        # error messages go through flask_babel, whose locale selector reads
        # request.accept_languages, so a request context is needed.
        self.app_context = self.app.test_request_context(
            '/translate', method='POST')
        self.app_context.push()
        db.create_all()
        patcher = mock.patch('app.translate.requests.post')
        self.post = patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def set_key(self, key='secret-key'):
        self.app.config['MS_TRANSLATOR_KEY'] = key

    # --- not configured ---------------------------------------------------

    def test_key_missing_from_config_returns_not_configured(self):
        del self.app.config['MS_TRANSLATOR_KEY']
        result = translate('Hello', 'en', 'es')
        self.assertEqual(result, NOT_CONFIGURED)
        self.assertIs(type(result), str)
        self.post.assert_not_called()

    def test_key_none_returns_not_configured(self):
        self.set_key(None)
        self.assertEqual(translate('Hello', 'en', 'es'), NOT_CONFIGURED)
        self.post.assert_not_called()

    def test_key_falsy_values_return_not_configured(self):
        for key in ('', 0, False, [], {}):
            with self.subTest(key=key):
                self.set_key(key)
                self.assertEqual(translate('Hello', 'en', 'es'),
                                 NOT_CONFIGURED)
        self.post.assert_not_called()

    def test_whitespace_key_is_treated_as_configured(self):
        # Current behaviour that looks like a bug: a whitespace-only key is
        # truthy, so it is sent to the service instead of being rejected.
        self.set_key('   ')
        self.post.return_value = make_response(401)
        self.assertEqual(translate('Hello', 'en', 'es'), FAILED)
        self.post.assert_called_once()
        self.assertEqual(
            self.post.call_args.kwargs['headers']['Ocp-Apim-Subscription-Key'],
            '   ')

    def test_not_configured_does_not_validate_arguments(self):
        self.set_key(None)
        self.assertEqual(translate(None, None, None), NOT_CONFIGURED)

    # --- success path -----------------------------------------------------

    def test_success_exact_request_and_return_value(self):
        self.set_key('secret-key')
        self.post.return_value = make_response(200, ok_payload('Hola'))
        result = translate('Hello', 'en', 'es')
        self.assertEqual(result, 'Hola')
        self.assertIs(type(result), str)
        self.post.assert_called_once()
        args, kwargs = self.post.call_args
        self.assertEqual(args, (BASE_URL + '&from=en&to=es',))
        self.assertEqual(kwargs['headers'], {
            'Ocp-Apim-Subscription-Key': 'secret-key',
            'Ocp-Apim-Subscription-Region': 'westus',
        })
        self.assertEqual(kwargs['json'], [{'Text': 'Hello'}])
        self.post.return_value.json.assert_called_once_with()

    def test_post_called_without_timeout(self):
        # Current behaviour that looks like a bug (ruff S113 / finding C11):
        # requests.post gets only headers= and json= -- no timeout (a hung
        # service blocks the worker forever) and no other options. Adding a
        # timeout is a behaviour change and is expected to fail ONLY this test.
        self.set_key()
        self.post.return_value = make_response(200, ok_payload('x'))
        translate('a', 'en', 'es')
        self.assertEqual(set(self.post.call_args.kwargs), {'headers', 'json'})
        self.assertNotIn('timeout', self.post.call_args.kwargs)

    def test_region_is_hardcoded_westus(self):
        # Current behaviour that looks like a bug: the subscription region is
        # hard-coded to 'westus' and cannot be configured.
        self.set_key('k')
        self.app.config['MS_TRANSLATOR_REGION'] = 'eastus'
        self.post.return_value = make_response(200, ok_payload('x'))
        translate('a', 'en', 'es')
        self.assertEqual(
            self.post.call_args.kwargs['headers'],
            {'Ocp-Apim-Subscription-Key': 'k',
             'Ocp-Apim-Subscription-Region': 'westus'})

    def test_url_is_positional_and_built_from_languages(self):
        self.set_key()
        self.post.return_value = make_response(200, ok_payload('x'))
        translate('a', 'fr', 'de')
        self.assertEqual(self.post.call_args.args,
                         (BASE_URL + '&from=fr&to=de',))

    def test_languages_are_not_url_encoded(self):
        # Current behaviour that looks like a bug: language codes are
        # interpolated into the query string without URL-encoding, so extra
        # query parameters can be injected.
        self.set_key()
        self.post.return_value = make_response(200, ok_payload('x'))
        translate('a', 'en&to=fr', 'es #x')
        self.assertEqual(self.post.call_args.args[0],
                         BASE_URL + '&from=en&to=fr&to=es #x')

    def test_language_none_and_empty_are_formatted_verbatim(self):
        # Current behaviour that looks like a bug: no validation, None is
        # rendered as the literal string 'None'.
        self.set_key()
        self.post.return_value = make_response(200, ok_payload('x'))
        translate('a', None, '')
        self.assertEqual(self.post.call_args.args[0],
                         BASE_URL + '&from=None&to=')

    def test_text_is_sent_unmodified(self):
        self.set_key()
        self.post.return_value = make_response(200, ok_payload('x'))
        for text in ('', '  spaced  ', 'ünïcødé <b>&</b>', None, 123):
            with self.subTest(text=text):
                translate(text, 'en', 'es')
                self.assertEqual(self.post.call_args.kwargs['json'],
                                 [{'Text': text}])

    def test_only_first_translation_is_returned(self):
        self.set_key()
        payload = [{'translations': [{'text': 'first'}, {'text': 'second'}]},
                   {'translations': [{'text': 'third'}]}]
        self.post.return_value = make_response(200, payload)
        self.assertEqual(translate('a', 'en', 'es'), 'first')

    def test_return_value_is_not_coerced_to_str(self):
        # Current behaviour that looks like a bug: whatever the service puts
        # in 'text' is returned as-is, even if it is not a string.
        self.set_key()
        for value in (None, 42, ['x'], ''):
            with self.subTest(value=value):
                self.post.return_value = make_response(
                    200, [{'translations': [{'text': value}]}])
                self.assertEqual(translate('a', 'en', 'es'), value)

    # --- failure path -----------------------------------------------------

    def test_non_200_status_returns_failed(self):
        self.set_key()
        for status in (201, 204, 301, 400, 401, 403, 404, 429, 500, 503):
            with self.subTest(status=status):
                self.post.return_value = make_response(status, ok_payload('x'))
                result = translate('a', 'en', 'es')
                self.assertEqual(result, FAILED)
                self.assertIs(type(result), str)
                self.post.return_value.json.assert_not_called()

    def test_status_code_compared_by_equality(self):
        # status_code is compared with != 200, so any value equal to 200
        # (e.g. 200.0) counts as success.
        self.set_key()
        self.post.return_value = make_response(200.0, ok_payload('ok'))
        self.assertEqual(translate('a', 'en', 'es'), 'ok')

    def test_request_exceptions_propagate(self):
        # Current behaviour that looks like a bug: network errors are not
        # caught and propagate to the caller (the /translate route -> 500).
        self.set_key()
        for exc in (requests.exceptions.ConnectionError('down'),
                    requests.exceptions.Timeout('slow'),
                    requests.exceptions.RequestException('boom')):
            with self.subTest(exc=type(exc).__name__):
                self.post.side_effect = exc
                with self.assertRaises(type(exc)) as cm:
                    translate('a', 'en', 'es')
                self.assertIs(cm.exception, exc)

    def test_malformed_200_response_raises(self):
        # Current behaviour that looks like a bug: an unexpected JSON shape on
        # a 200 response raises instead of returning the failure message.
        self.set_key()
        cases = [
            ([], IndexError),
            ([{}], KeyError),
            ([{'translations': []}], IndexError),
            ([{'translations': [{}]}], KeyError),
            ({'error': 'x'}, KeyError),
            (None, TypeError),
        ]
        for payload, exc_type in cases:
            with self.subTest(payload=payload):
                self.post.return_value = make_response(200, payload)
                with self.assertRaises(exc_type):
                    translate('a', 'en', 'es')

    def test_invalid_json_on_200_propagates(self):
        self.set_key()
        r = make_response(200)
        r.json.side_effect = requests.exceptions.JSONDecodeError('x', 'doc', 0)
        self.post.return_value = r
        with self.assertRaises(requests.exceptions.JSONDecodeError):
            translate('a', 'en', 'es')

    # --- context / localization -------------------------------------------

    def test_error_paths_need_request_context(self):
        # Current behaviour that looks like a bug: with only an app context
        # (no request), the error messages cannot be built because the babel
        # locale selector touches `request`, so RuntimeError is raised.
        self.app_context.pop()
        try:
            with self.app.app_context():
                self.app.config['MS_TRANSLATOR_KEY'] = None
                with self.assertRaises(RuntimeError):
                    translate('a', 'en', 'es')
                self.post.assert_not_called()
                self.app.config['MS_TRANSLATOR_KEY'] = 'k'
                self.post.return_value = make_response(500)
                with self.assertRaises(RuntimeError):
                    translate('a', 'en', 'es')
                self.post.assert_called_once()
        finally:
            self.app_context.push()

    def test_success_path_works_with_app_context_only(self):
        self.app_context.pop()
        try:
            with self.app.app_context():
                self.app.config['MS_TRANSLATOR_KEY'] = 'k'
                self.post.return_value = make_response(200, ok_payload('Hola'))
                self.assertEqual(translate('Hello', 'en', 'es'), 'Hola')
        finally:
            self.app_context.push()

    @unittest.skipIf(
        glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'app', 'translations', '*', 'LC_MESSAGES',
                               '*.mo')),
        'compiled .mo catalogs present; messages would be localized')
    def test_spanish_request_gets_english_messages_without_compiled_catalog(
            self):
        # Current behaviour that looks like a bug: *.mo files are gitignored
        # and not compiled in a fresh checkout/CI, so a Spanish request still
        # gets the English error messages.
        self.set_key(None)
        with self.app.test_request_context(
                '/translate', method='POST',
                headers={'Accept-Language': 'es'}):
            self.assertEqual(translate('a', 'en', 'es'), NOT_CONFIGURED)
            self.set_key('k')
            self.post.return_value = make_response(500)
            self.assertEqual(translate('a', 'en', 'es'), FAILED)

    def test_requires_app_context(self):
        self.app_context.pop()
        try:
            with self.assertRaises(RuntimeError):
                translate('a', 'en', 'es')
        finally:
            self.app_context.push()
        self.post.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
