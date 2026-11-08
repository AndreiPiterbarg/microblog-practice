"""Golden (characterization) tests for the login view, app/auth/routes.py:14-30.

These pin the CURRENT behaviour of ``app.auth.routes.login`` (Flask request
-> Flask-WTF LoginForm -> flash/redirect/render through Werkzeug and Jinja2)
so that dependency upgrades can be checked for zero behaviour change. They do
not describe intended behaviour.

Requests are made without an outer app context pushed: Flask reuses an
already-pushed app context for requests, so Flask-Login's per-context
``g._login_user`` cache would otherwise leak the logged-in user across
requests and test clients.
"""
import unittest
from unittest import mock
from urllib.parse import quote

from flask import template_rendered

from app import create_app, db
from app.auth import routes as auth_routes
from app.auth.forms import LoginForm
from app.models import User
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


class NoCSRFTestConfig(TestConfig):
    WTF_CSRF_ENABLED = False


class LoginViewGoldenBase(unittest.TestCase):
    config_class = NoCSRFTestConfig

    def setUp(self):
        self.app = create_app(self.config_class)
        with self.app.app_context():
            db.create_all()
            u = User(username='susan', email='susan@example.com')
            u.set_password('cat')
            db.session.add(u)
            db.session.commit()
            self.user_id = u.id
            self.last_seen = u.last_seen
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def post_login(self, data, next_=None, client=None):
        url = '/auth/login'
        if next_ is not None:
            url += '?next=' + quote(next_, safe='')
        return (client or self.client).post(url, data=data)

    def session(self, client=None):
        with (client or self.client).session_transaction() as sess:
            return dict(sess)

    def cookies(self, response):
        return [c.split('=', 1)[0] for c in response.headers.getlist('Set-Cookie')]


class LoginGetGoldenCase(LoginViewGoldenBase):
    def test_get_anonymous_renders_login_template(self):
        recorded = []

        def record(sender, template, context, **extra):
            recorded.append((template.name, context))

        template_rendered.connect(record, self.app)
        try:
            r = self.client.get('/auth/login')
        finally:
            template_rendered.disconnect(record, self.app)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers['Content-Type'], 'text/html; charset=utf-8')
        self.assertEqual(recorded[0][0], 'auth/login.html')
        self.assertEqual(recorded[0][1]['title'], 'Sign In')
        self.assertIsInstance(recorded[0][1]['form'], LoginForm)
        self.assertEqual([name for name, _ in recorded],
                         ['auth/login.html'])

    def test_get_anonymous_html_content(self):
        r = self.client.get('/auth/login')
        html = r.get_data(as_text=True)
        self.assertIn('<title>Sign In - Microblog</title>', html)
        self.assertIn('<h1>Sign In</h1>', html)
        self.assertIn('<form action="" method="post">', html)
        self.assertIn('<input autofocus class="form-control" id="username" '
                      'name="username" required type="text" value="">', html)
        self.assertIn('<input class="form-control" id="password" '
                      'name="password" required type="password" value="">',
                      html)
        self.assertIn('<input class="form-check-input" id="remember_me" '
                      'name="remember_me" type="checkbox" value="y">', html)
        self.assertIn('<input class="btn btn-primary mb-3" id="submit" '
                      'name="submit" type="submit" value="Sign In">', html)
        self.assertIn('<a href="/auth/register">Click to Register!</a>', html)
        self.assertIn('<a href="/auth/reset_password_request">'
                      'Click to Reset It</a>', html)
        self.assertNotIn('csrf_token', html)
        self.assertNotIn('alert-info', html)

    def test_get_does_not_log_in(self):
        self.client.get('/auth/login')
        self.assertNotIn('_user_id', self.session())

    def test_head_allowed(self):
        r = self.client.head('/auth/login')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, b'')

    def test_other_methods_not_allowed(self):
        for method in ('put', 'delete', 'patch'):
            r = getattr(self.client, method)('/auth/login')
            self.assertEqual(r.status_code, 405)
            self.assertEqual(sorted(r.headers['Allow'].split(', ')),
                             ['GET', 'HEAD', 'OPTIONS', 'POST'])

    def test_title_and_flash_use_gettext(self):
        with mock.patch.object(auth_routes, '_',
                               side_effect=lambda s: '<<' + s + '>>') as g:
            r = self.client.get('/auth/login')
            self.assertIn('<title>&lt;&lt;Sign In&gt;&gt; - Microblog</title>',
                          r.get_data(as_text=True))
            self.assertEqual(g.call_args_list, [mock.call('Sign In')])
            g.reset_mock()
            self.post_login({'username': 'susan', 'password': 'dog'})
            self.assertEqual(g.call_args_list,
                             [mock.call('Invalid username or password')])
        self.assertEqual(self.session()['_flashes'],
                         [('message', '<<Invalid username or password>>')])


class LoginPostSuccessGoldenCase(LoginViewGoldenBase):
    def test_success_redirects_to_index_and_logs_in(self):
        r = self.post_login({'username': 'susan', 'password': 'cat'})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers['Location'], '/index')
        self.assertEqual(self.cookies(r), ['session'])
        sess = self.session()
        self.assertEqual(sess['_user_id'], str(self.user_id))
        self.assertIs(sess['_fresh'], True)
        self.assertNotIn('_flashes', sess)

    def test_success_calls_login_user_with_remember_false(self):
        with mock.patch.object(auth_routes, 'login_user',
                               wraps=auth_routes.login_user) as lu:
            self.post_login({'username': 'susan', 'password': 'cat'})
        self.assertEqual(lu.call_count, 1)
        args, kwargs = lu.call_args
        self.assertEqual(len(args), 1)
        self.assertEqual(args[0].id, self.user_id)
        self.assertEqual(kwargs, {'remember': False})

    def test_success_with_remember_me_sets_remember_cookie(self):
        with mock.patch.object(auth_routes, 'login_user',
                               wraps=auth_routes.login_user) as lu:
            r = self.post_login({'username': 'susan', 'password': 'cat',
                                 'remember_me': 'y'})
        self.assertEqual(lu.call_args.kwargs, {'remember': True})
        self.assertEqual(r.headers['Location'], '/index')
        self.assertEqual(self.cookies(r), ['remember_token', 'session'])
        remember = r.headers.getlist('Set-Cookie')[0]
        self.assertTrue(remember.startswith(
            f'remember_token={self.user_id}|'))
        self.assertIn('; HttpOnly; Path=/', remember)

    def test_remember_me_any_non_false_value_is_true(self):
        # Current behaviour that looks like a bug: BooleanField treats any
        # submitted value other than 'false'/'' as checked, so
        # remember_me='n' (or '0', 'off') still sets a remember cookie.
        for value in ('n', '0', 'off'):
            client = self.app.test_client()
            r = self.post_login({'username': 'susan', 'password': 'cat',
                                 'remember_me': value}, client=client)
            self.assertEqual(self.cookies(r), ['remember_token', 'session'],
                             value)
        for value in ('false', ''):
            client = self.app.test_client()
            r = self.post_login({'username': 'susan', 'password': 'cat',
                                 'remember_me': value}, client=client)
            self.assertEqual(self.cookies(r), ['session'], value)

    def test_success_does_not_update_last_seen(self):
        self.post_login({'username': 'susan', 'password': 'cat'})
        with self.app.app_context():
            self.assertEqual(db.session.get(User, self.user_id).last_seen,
                             self.last_seen)

    def test_password_is_case_and_whitespace_sensitive(self):
        for pw in ('Cat', ' cat', 'cat '):
            client = self.app.test_client()
            r = self.post_login({'username': 'susan', 'password': pw},
                                client=client)
            self.assertEqual(r.headers['Location'], '/auth/login', pw)

    def test_username_is_case_and_whitespace_sensitive(self):
        for un in ('Susan', ' susan', 'susan ', 'SUSAN'):
            client = self.app.test_client()
            r = self.post_login({'username': un, 'password': 'cat'},
                                client=client)
            self.assertEqual(r.headers['Location'], '/auth/login', un)
            self.assertNotIn('_user_id', self.session(client))


class LoginNextParamGoldenCase(LoginViewGoldenBase):
    def assert_next_redirect(self, next_, expected):
        client = self.app.test_client()
        r = self.post_login({'username': 'susan', 'password': 'cat'},
                            next_=next_, client=client)
        self.assertEqual(r.status_code, 302, next_)
        self.assertEqual(r.headers['Location'], expected, next_)
        self.assertEqual(self.session(client)['_user_id'], str(self.user_id))

    def test_empty_next_goes_to_index(self):
        self.assert_next_redirect('', '/index')

    def test_relative_path_next_is_followed(self):
        self.assert_next_redirect('/explore', '/explore')
        self.assert_next_redirect('/user/susan?x=1', '/user/susan?x=1')

    def test_path_without_leading_slash_is_followed(self):
        self.assert_next_redirect('explore', 'explore')

    def test_next_with_netloc_goes_to_index(self):
        self.assert_next_redirect('http://evil.com/x', '/index')
        self.assert_next_redirect('//evil.com', '/index')
        self.assert_next_redirect('https://evil.com', '/index')

    def test_absolute_same_host_next_goes_to_index(self):
        # Current behaviour that looks like a bug: an absolute URL to the
        # app's own host is rejected because only an empty netloc is allowed.
        self.assert_next_redirect('http://localhost/explore', '/index')

    def test_backslash_next_is_followed(self):
        # Current behaviour that looks like a bug (open redirect): urlsplit
        # sees no netloc in '/\\evil.com', but browsers treat it as
        # '//evil.com'.
        self.assert_next_redirect('/\\evil.com', '/\\evil.com')

    def test_scheme_without_netloc_next_is_followed(self):
        # Current behaviour that looks like a bug: schemes are not checked,
        # so 'javascript:' and 'https:host' URLs pass the netloc check.
        self.assert_next_redirect('javascript:alert(1)', 'javascript:alert(1)')
        self.assert_next_redirect('https:evil.com', 'https:evil.com')

    def test_next_is_ignored_on_failed_login(self):
        # Current behaviour that looks like a bug: the redirect back to the
        # login page drops the ?next= parameter.
        r = self.post_login({'username': 'susan', 'password': 'dog'},
                            next_='/explore')
        self.assertEqual(r.headers['Location'], '/auth/login')


class LoginPostFailureGoldenCase(LoginViewGoldenBase):
    def test_wrong_password_flashes_and_redirects(self):
        r = self.post_login({'username': 'susan', 'password': 'dog'})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers['Location'], '/auth/login')
        sess = self.session()
        self.assertEqual(sess, {'_flashes': [
            ('message', 'Invalid username or password')]})

    def test_unknown_user_flashes_same_message(self):
        r = self.post_login({'username': 'nobody', 'password': 'cat'})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers['Location'], '/auth/login')
        self.assertEqual(self.session()['_flashes'],
                         [('message', 'Invalid username or password')])

    def test_flash_is_rendered_on_next_get_once(self):
        self.post_login({'username': 'susan', 'password': 'dog'})
        html = self.client.get('/auth/login').get_data(as_text=True)
        self.assertEqual(html.count('alert-info'), 1)
        self.assertIn('<div class="alert alert-info" role="alert">'
                      'Invalid username or password</div>', html)
        html = self.client.get('/auth/login').get_data(as_text=True)
        self.assertNotIn('alert-info', html)

    def test_repeated_failures_accumulate_flashes(self):
        self.post_login({'username': 'susan', 'password': 'dog'})
        self.post_login({'username': 'susan', 'password': 'dog'})
        self.assertEqual(self.session()['_flashes'],
                         [('message', 'Invalid username or password')] * 2)

    def test_missing_fields_rerender_with_errors(self):
        r = self.post_login({})
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertEqual(html.count(
            '<div class="invalid-feedback">This field is required.</div>'), 2)
        self.assertIn('<input autofocus class="form-control is-invalid" '
                      'id="username" name="username" required type="text" '
                      'value="">', html)
        self.assertIn('<input class="form-control is-invalid" id="password" '
                      'name="password" required type="password" value="">',
                      html)
        self.assertNotIn('_flashes', self.session())
        self.assertNotIn('_user_id', self.session())

    def test_missing_password_keeps_username_value(self):
        r = self.post_login({'username': 'susan'})
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn('<input autofocus class="form-control" id="username" '
                      'name="username" required type="text" value="susan">',
                      html)
        self.assertEqual(html.count(
            '<div class="invalid-feedback">This field is required.</div>'), 1)

    def test_whitespace_only_fields_fail_validation(self):
        r = self.post_login({'username': '   ', 'password': '   '})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_data(as_text=True).count(
            'This field is required.'), 2)

    def test_user_without_password_hash_raises(self):
        # Current behaviour that looks like a bug: a user row with
        # password_hash NULL makes check_password raise instead of failing
        # the login (a 500 outside TESTING).
        with self.app.app_context():
            db.session.add(User(username='nopw', email='nopw@example.com'))
            db.session.commit()
        with self.assertRaises(AttributeError) as cm:
            self.post_login({'username': 'nopw', 'password': 'x'})
        self.assertEqual(str(cm.exception),
                         "'NoneType' object has no attribute 'split'")


class LoginAuthenticatedGoldenCase(LoginViewGoldenBase):
    def setUp(self):
        super().setUp()
        self.post_login({'username': 'susan', 'password': 'cat'})

    def test_get_when_authenticated_redirects_to_index(self):
        with mock.patch.object(auth_routes, 'render_template') as rt:
            r = self.client.get('/auth/login')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers['Location'], '/index')
        rt.assert_not_called()

    def test_post_when_authenticated_ignores_form_and_next(self):
        with mock.patch.object(auth_routes, 'login_user') as lu:
            r = self.post_login({'username': 'nobody', 'password': 'x'},
                                next_='/explore')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers['Location'], '/index')
        lu.assert_not_called()
        self.assertNotIn('_flashes', self.session())


class LoginCSRFGoldenCase(LoginViewGoldenBase):
    config_class = TestConfig

    def test_get_includes_csrf_token(self):
        html = self.client.get('/auth/login').get_data(as_text=True)
        self.assertIn('<input id="csrf_token" name="csrf_token" '
                      'type="hidden" value="', html)

    def test_post_without_csrf_token_rerenders(self):
        r = self.post_login({'username': 'susan', 'password': 'cat'})
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn('<div class="invalid-feedback">'
                      'The CSRF token is missing.</div>', html)
        self.assertNotIn('_user_id', self.session())

    def test_post_with_csrf_token_logs_in(self):
        html = self.client.get('/auth/login').get_data(as_text=True)
        marker = 'name="csrf_token" type="hidden" value="'
        start = html.index(marker) + len(marker)
        token = html[start:html.index('"', start)]
        r = self.post_login({'username': 'susan', 'password': 'cat',
                             'csrf_token': token})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers['Location'], '/index')
        self.assertEqual(self.session()['_user_id'], str(self.user_id))


if __name__ == '__main__':
    unittest.main(verbosity=2)
