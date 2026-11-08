#!/usr/bin/env python
"""Golden (characterization) tests for U12: config.py (module-level
load_dotenv and the Config class).

Config attributes are evaluated once, at import time, from os.environ after
load_dotenv has run. Each test therefore re-executes config.py as a fresh,
uniquely named module under a controlled environment, leaving the real
`config` module (used by the app and tests.py) untouched.
"""
import importlib.util
import itertools
import os
import shutil
import tempfile
import unittest
from unittest import mock

from app import create_app, db
import config
from config import Config

REPO_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH = os.path.join(REPO_DIR, 'config.py')
_counter = itertools.count()


def load_config_module(path=CONFIG_PATH, env=None, mock_dotenv=True):
    """Execute config.py fresh with os.environ replaced by `env`.

    Returns (module, load_dotenv_mock_or_None, environ_after_import).
    """
    name = f'_golden_u12_config_{next(_counter)}'
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, env or {}, clear=True):
        if mock_dotenv:
            with mock.patch('dotenv.load_dotenv') as load_dotenv:
                spec.loader.exec_module(module)
        else:
            load_dotenv = None
            spec.loader.exec_module(module)
        environ_after = dict(os.environ)
    return module, load_dotenv, environ_after


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


class ModuleLevelLoadDotenvCase(unittest.TestCase):
    def test_basedir_is_absolute_directory_of_config_py(self):
        module, _, _ = load_config_module()
        self.assertEqual(module.basedir, REPO_DIR)
        self.assertTrue(os.path.isabs(module.basedir))
        self.assertEqual(config.basedir, REPO_DIR)

    def test_load_dotenv_called_once_with_basedir_dotenv_only(self):
        _, load_dotenv, _ = load_config_module()
        load_dotenv.assert_called_once_with(os.path.join(REPO_DIR, '.env'))
        self.assertEqual(load_dotenv.call_args.kwargs, {})

    def test_module_public_names(self):
        module, _, _ = load_config_module()
        public = sorted(n for n in vars(module) if not n.startswith('_'))
        self.assertEqual(public, ['Config', 'basedir', 'load_dotenv', 'os'])


class DotenvFileIntegrationCase(unittest.TestCase):
    """Real python-dotenv against a .env next to a copy of config.py."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.config_path = os.path.join(self.tmpdir, 'config.py')
        shutil.copyfile(CONFIG_PATH, self.config_path)

    def write_env(self, text):
        with open(os.path.join(self.tmpdir, '.env'), 'w') as f:
            f.write(text)

    def load(self, env=None):
        return load_config_module(self.config_path, env=env,
                                  mock_dotenv=False)

    def test_missing_dotenv_file_is_silently_ignored(self):
        module, _, environ_after = self.load()
        self.assertEqual(environ_after, {})
        self.assertEqual(module.Config.SECRET_KEY, 'you-will-never-guess')
        self.assertEqual(module.Config.SQLALCHEMY_DATABASE_URI,
                         'sqlite:///' + os.path.join(self.tmpdir, 'app.db'))

    def test_dotenv_values_feed_config_and_environ(self):
        self.write_env(
            'SECRET_KEY=from-dotenv\n'
            'DATABASE_URL=postgres://h/db\n'
            'MAIL_PORT=587\n'
            'MAIL_USE_TLS=1\n'
            'REDIS_URL=redis://cache:6379/0\n')
        module, _, environ_after = self.load()
        self.assertEqual(module.Config.SECRET_KEY, 'from-dotenv')
        self.assertEqual(module.Config.SQLALCHEMY_DATABASE_URI,
                         'postgresql://h/db')
        self.assertEqual(module.Config.MAIL_PORT, 587)
        self.assertIs(module.Config.MAIL_USE_TLS, True)
        self.assertEqual(module.Config.REDIS_URL, 'redis://cache:6379/0')
        # Side effect: values are exported into os.environ.
        self.assertEqual(environ_after, {
            'SECRET_KEY': 'from-dotenv',
            'DATABASE_URL': 'postgres://h/db',
            'MAIL_PORT': '587',
            'MAIL_USE_TLS': '1',
            'REDIS_URL': 'redis://cache:6379/0',
        })

    def test_existing_environment_wins_over_dotenv(self):
        self.write_env('SECRET_KEY=from-dotenv\nMAIL_SERVER=file-smtp\n')
        module, _, environ_after = self.load({'SECRET_KEY': 'from-env'})
        self.assertEqual(module.Config.SECRET_KEY, 'from-env')
        self.assertEqual(module.Config.MAIL_SERVER, 'file-smtp')
        self.assertEqual(environ_after,
                         {'SECRET_KEY': 'from-env', 'MAIL_SERVER': 'file-smtp'})

    def test_existing_empty_environment_value_wins_over_dotenv(self):
        # Current behaviour that looks like a bug: an empty SECRET_KEY in the
        # environment blocks the .env value, then `or` falls back to the
        # hard-coded default instead of the .env secret.
        self.write_env('SECRET_KEY=from-dotenv\n')
        module, _, environ_after = self.load({'SECRET_KEY': ''})
        self.assertEqual(module.Config.SECRET_KEY, 'you-will-never-guess')
        self.assertEqual(environ_after, {'SECRET_KEY': ''})

    def test_dotenv_parsing_rules(self):
        self.write_env(
            'MAIL_SERVER=smtp.example.com\n'
            'export MAIL_USERNAME="two words"\n'
            'SERVER_NAME=${MAIL_SERVER}:5000\n'
            '# a comment line\n'
            'MS_TRANSLATOR_KEY=abc # trailing comment\n'
            'LOG_TO_STDOUT=\n'
            'ELASTICSEARCH_URL\n'
            "MAIL_PASSWORD='x=y'\n")
        module, _, environ_after = self.load()
        c = module.Config
        self.assertEqual(c.MAIL_SERVER, 'smtp.example.com')
        self.assertEqual(c.MAIL_USERNAME, 'two words')
        self.assertEqual(c.SERVER_NAME, 'smtp.example.com:5000')
        self.assertEqual(c.MS_TRANSLATOR_KEY, 'abc')
        self.assertEqual(c.LOG_TO_STDOUT, '')
        self.assertIsNone(c.ELASTICSEARCH_URL)
        self.assertEqual(c.MAIL_PASSWORD, 'x=y')
        self.assertEqual(environ_after, {
            'MAIL_SERVER': 'smtp.example.com',
            'MAIL_USERNAME': 'two words',
            'SERVER_NAME': 'smtp.example.com:5000',
            'MS_TRANSLATOR_KEY': 'abc',
            'LOG_TO_STDOUT': '',
            'MAIL_PASSWORD': 'x=y',
        })

    def test_variable_expansion_prefers_existing_environment(self):
        self.write_env('SERVER_NAME=${HOSTNAME_X}:80\n')
        module, _, _ = self.load({'HOSTNAME_X': 'envhost'})
        self.assertEqual(module.Config.SERVER_NAME, 'envhost:80')

    def test_undefined_variable_expands_to_empty(self):
        self.write_env('SERVER_NAME=${UNDEFINED_X}:80\n')
        module, _, _ = self.load()
        self.assertEqual(module.Config.SERVER_NAME, ':80')


class ConfigDefaultsCase(unittest.TestCase):
    def setUp(self):
        module, _, _ = load_config_module()
        self.c = module.Config

    def test_defaults_with_empty_environment(self):
        c = self.c
        self.assertEqual(c.SECRET_KEY, 'you-will-never-guess')
        self.assertIsNone(c.SERVER_NAME)
        self.assertEqual(c.SQLALCHEMY_DATABASE_URI,
                         'sqlite:///' + os.path.join(REPO_DIR, 'app.db'))
        self.assertIsNone(c.LOG_TO_STDOUT)
        self.assertIsNone(c.MAIL_SERVER)
        self.assertEqual(c.MAIL_PORT, 25)
        self.assertIs(type(c.MAIL_PORT), int)
        self.assertIs(c.MAIL_USE_TLS, False)
        self.assertIsNone(c.MAIL_USERNAME)
        self.assertIsNone(c.MAIL_PASSWORD)
        self.assertEqual(c.ADMINS, ['your-email@example.com'])
        self.assertEqual(c.LANGUAGES, ['en', 'es'])
        self.assertIsNone(c.MS_TRANSLATOR_KEY)
        self.assertIsNone(c.ELASTICSEARCH_URL)
        self.assertEqual(c.REDIS_URL, 'redis://')
        self.assertEqual(c.POSTS_PER_PAGE, 25)
        self.assertIs(type(c.POSTS_PER_PAGE), int)

    def test_exact_set_of_uppercase_settings(self):
        names = sorted(n for n in vars(self.c) if n.isupper())
        self.assertEqual(names, [
            'ADMINS', 'ELASTICSEARCH_URL', 'LANGUAGES', 'LOG_TO_STDOUT',
            'MAIL_PASSWORD', 'MAIL_PORT', 'MAIL_SERVER', 'MAIL_USERNAME',
            'MAIL_USE_TLS', 'MS_TRANSLATOR_KEY', 'POSTS_PER_PAGE',
            'REDIS_URL', 'SECRET_KEY', 'SERVER_NAME',
            'SQLALCHEMY_DATABASE_URI',
        ])

    def test_config_is_plain_class(self):
        self.assertEqual(self.c.__bases__, (object,))


class ConfigFromEnvironmentCase(unittest.TestCase):
    def config(self, **env):
        module, _, _ = load_config_module(env=env)
        return module.Config

    def test_all_values_from_environment(self):
        c = self.config(
            SECRET_KEY='not-a-secret', SERVER_NAME='example.com:5000',
            DATABASE_URL='mysql://h/db', LOG_TO_STDOUT='1',
            MAIL_SERVER='smtp.example.com', MAIL_PORT='587',
            MAIL_USE_TLS='1', MAIL_USERNAME='user', MAIL_PASSWORD='placeholder',
            MS_TRANSLATOR_KEY='key', ELASTICSEARCH_URL='http://es:9200',
            REDIS_URL='redis://r:6379/1')
        self.assertEqual(c.SECRET_KEY, 'not-a-secret')
        self.assertEqual(c.SERVER_NAME, 'example.com:5000')
        self.assertEqual(c.SQLALCHEMY_DATABASE_URI, 'mysql://h/db')
        self.assertEqual(c.LOG_TO_STDOUT, '1')
        self.assertEqual(c.MAIL_SERVER, 'smtp.example.com')
        self.assertEqual(c.MAIL_PORT, 587)
        self.assertIs(c.MAIL_USE_TLS, True)
        self.assertEqual(c.MAIL_USERNAME, 'user')
        self.assertEqual(c.MAIL_PASSWORD, 'placeholder')
        self.assertEqual(c.MS_TRANSLATOR_KEY, 'key')
        self.assertEqual(c.ELASTICSEARCH_URL, 'http://es:9200')
        self.assertEqual(c.REDIS_URL, 'redis://r:6379/1')
        # Not configurable from the environment.
        self.assertEqual(c.ADMINS, ['your-email@example.com'])
        self.assertEqual(c.LANGUAGES, ['en', 'es'])
        self.assertEqual(c.POSTS_PER_PAGE, 25)

    def test_unrelated_and_lowercase_variables_are_ignored(self):
        c = self.config(secret_key='lower', POSTS_PER_PAGE='5',
                        ADMINS='a@b.c', DATABASE_URI='postgres://x')
        self.assertEqual(c.SECRET_KEY, 'you-will-never-guess')
        self.assertEqual(c.POSTS_PER_PAGE, 25)
        self.assertEqual(c.ADMINS, ['your-email@example.com'])
        self.assertEqual(c.SQLALCHEMY_DATABASE_URI,
                         'sqlite:///' + os.path.join(REPO_DIR, 'app.db'))

    def test_values_are_frozen_at_import_time(self):
        module, _, _ = load_config_module(env={'SECRET_KEY': 'first'})
        with mock.patch.dict(os.environ, {'SECRET_KEY': 'second'}):
            self.assertEqual(module.Config.SECRET_KEY, 'first')

    # SECRET_KEY
    def test_empty_secret_key_falls_back_to_default(self):
        self.assertEqual(self.config(SECRET_KEY='').SECRET_KEY,
                         'you-will-never-guess')

    def test_whitespace_secret_key_kept_verbatim(self):
        self.assertEqual(self.config(SECRET_KEY=' ').SECRET_KEY, ' ')

    # SQLALCHEMY_DATABASE_URI
    def test_postgres_scheme_rewritten_to_postgresql(self):
        self.assertEqual(
            self.config(DATABASE_URL='postgres://h:5432/db')
            .SQLALCHEMY_DATABASE_URI, 'postgresql://h:5432/db')

    def test_postgresql_scheme_unchanged(self):
        self.assertEqual(
            self.config(DATABASE_URL='postgresql://u@h/db')
            .SQLALCHEMY_DATABASE_URI, 'postgresql://u@h/db')

    def test_postgres_replacement_is_not_anchored_to_scheme(self):
        # Current behaviour that looks like a bug: str.replace rewrites every
        # 'postgres://' occurrence, not just the URL scheme prefix.
        self.assertEqual(
            self.config(DATABASE_URL='sqlite:///x?next=postgres://y')
            .SQLALCHEMY_DATABASE_URI, 'sqlite:///x?next=postgresql://y')
        self.assertEqual(
            self.config(DATABASE_URL='postgres://a/postgres://b')
            .SQLALCHEMY_DATABASE_URI, 'postgresql://a/postgresql://b')

    def test_postgres_replacement_is_case_sensitive(self):
        self.assertEqual(
            self.config(DATABASE_URL='POSTGRES://u@h/db')
            .SQLALCHEMY_DATABASE_URI, 'POSTGRES://u@h/db')

    def test_empty_database_url_falls_back_to_sqlite(self):
        self.assertEqual(
            self.config(DATABASE_URL='').SQLALCHEMY_DATABASE_URI,
            'sqlite:///' + os.path.join(REPO_DIR, 'app.db'))

    # MAIL_PORT
    def test_mail_port_empty_falls_back_to_25(self):
        self.assertEqual(self.config(MAIL_PORT='').MAIL_PORT, 25)

    def test_mail_port_surrounding_whitespace_accepted(self):
        self.assertEqual(self.config(MAIL_PORT=' 465 ').MAIL_PORT, 465)

    def test_mail_port_zero_and_negative_accepted(self):
        self.assertEqual(self.config(MAIL_PORT='0').MAIL_PORT, 0)
        self.assertEqual(self.config(MAIL_PORT='-1').MAIL_PORT, -1)

    def test_mail_port_non_integer_raises_at_import(self):
        # Current behaviour that looks like a bug: a malformed MAIL_PORT makes
        # importing config.py (and so the whole app) fail.
        with self.assertRaises(ValueError) as cm:
            self.config(MAIL_PORT='smtp')
        self.assertEqual(str(cm.exception),
                         "invalid literal for int() with base 10: 'smtp'")
        with self.assertRaises(ValueError):
            self.config(MAIL_PORT='25.0')

    # MAIL_USE_TLS
    def test_mail_use_tls_true_for_any_set_value(self):
        # Current behaviour that looks like a bug: only presence is checked,
        # so '', '0', 'false' and 'no' all enable TLS.
        for value in ('1', 'true', '', '0', 'false', 'False', 'no'):
            with self.subTest(value=value):
                self.assertIs(self.config(MAIL_USE_TLS=value).MAIL_USE_TLS,
                              True)

    # Raw string passthroughs
    def test_log_to_stdout_is_raw_string(self):
        # Current behaviour that looks like a bug: the raw string is kept,
        # so LOG_TO_STDOUT='0' / 'false' is truthy for create_app.
        for value in ('0', 'false', ''):
            with self.subTest(value=value):
                self.assertEqual(
                    self.config(LOG_TO_STDOUT=value).LOG_TO_STDOUT, value)

    def test_empty_strings_kept_for_plain_get_settings(self):
        c = self.config(SERVER_NAME='', MAIL_SERVER='', MAIL_USERNAME='',
                        MAIL_PASSWORD='', MS_TRANSLATOR_KEY='',
                        ELASTICSEARCH_URL='')
        for name in ('SERVER_NAME', 'MAIL_SERVER', 'MAIL_USERNAME',
                     'MAIL_PASSWORD', 'MS_TRANSLATOR_KEY',
                     'ELASTICSEARCH_URL'):
            with self.subTest(name=name):
                self.assertEqual(getattr(c, name), '')

    def test_empty_redis_url_falls_back_to_default(self):
        self.assertEqual(self.config(REDIS_URL='').REDIS_URL, 'redis://')


class ConfigClassQuirksCase(unittest.TestCase):
    def test_list_settings_are_shared_mutable_class_attributes(self):
        # Current behaviour that looks like a bug: ADMINS and LANGUAGES are
        # mutable lists shared by Config and every subclass.
        self.assertIs(TestConfig.ADMINS, Config.ADMINS)
        self.assertIs(TestConfig.LANGUAGES, Config.LANGUAGES)

    def test_each_import_creates_new_list_objects(self):
        m1, _, _ = load_config_module()
        m2, _, _ = load_config_module()
        self.assertIsNot(m1.Config.ADMINS, m2.Config.ADMINS)
        self.assertEqual(m1.Config.ADMINS, m2.Config.ADMINS)


class CreateAppConfigCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_config_attributes_copied_into_app_config(self):
        for name in ('SECRET_KEY', 'SERVER_NAME', 'LOG_TO_STDOUT',
                     'MAIL_SERVER', 'MAIL_PORT', 'MAIL_USE_TLS',
                     'MAIL_USERNAME', 'MAIL_PASSWORD', 'ADMINS',
                     'LANGUAGES', 'MS_TRANSLATOR_KEY', 'REDIS_URL',
                     'POSTS_PER_PAGE'):
            with self.subTest(name=name):
                self.assertEqual(self.app.config[name],
                                 getattr(Config, name))
        self.assertIs(self.app.config['ADMINS'], Config.ADMINS)
        self.assertEqual(self.app.config['SQLALCHEMY_DATABASE_URI'],
                         'sqlite://')
        self.assertIsNone(self.app.config['ELASTICSEARCH_URL'])
        self.assertIs(self.app.config['TESTING'], True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
