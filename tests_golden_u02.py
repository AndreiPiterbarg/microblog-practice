"""Golden (characterization) tests for U02: app/cli.py `update`
(`flask translate update`).

These pin the CURRENT behaviour of the command so that the fixes for ruff
findings C04-C07 (S605/S607 on the two os.system calls) can be checked for
zero behaviour change. os.system and os.remove are patched at the boundary,
so pybabel is never run and no files are touched.
"""
import unittest
from unittest import mock

import click

from app import cli, create_app, db
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


EXTRACT_CMD = 'pybabel extract -F babel.cfg -k _l -o messages.pot .'
UPDATE_CMD = 'pybabel update -i messages.pot -d app/translations'


class TranslateUpdateGoldenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.runner = self.app.test_cli_runner()

        system_patcher = mock.patch('app.cli.os.system', return_value=0)
        remove_patcher = mock.patch('app.cli.os.remove')
        self.system = system_patcher.start()
        self.remove = remove_patcher.start()
        self.addCleanup(system_patcher.stop)
        self.addCleanup(remove_patcher.stop)

        self.events = []
        self.system.side_effect = self._record_system
        self.remove.side_effect = lambda path: self.events.append(
            ('remove', path))
        self.system_results = []

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _record_system(self, command):
        self.events.append(('system', command))
        return self.system_results.pop(0) if self.system_results else 0

    def call_callback(self):
        # The Flask AppGroup wraps the callback in with_appcontext, which
        # needs an active click context.
        with click.Context(cli.update) as ctx:
            return ctx.invoke(cli.update.callback)

    def invoke(self, *args):
        return self.runner.invoke(args=['translate', 'update', *args])

    # --- normal case -----------------------------------------------------

    def test_success_runs_extract_then_update_then_removes_pot(self):
        result = self.invoke()
        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.exception)
        self.assertEqual(result.output, '')
        self.assertEqual(self.events, [
            ('system', EXTRACT_CMD),
            ('system', UPDATE_CMD),
            ('remove', 'messages.pot'),
        ])
        self.assertEqual(self.system.call_args_list,
                         [mock.call(EXTRACT_CMD), mock.call(UPDATE_CMD)])
        self.remove.assert_called_once_with('messages.pot')

    def test_commands_are_single_shell_strings(self):
        # os.system receives one positional str per call (shell=True style),
        # with no keyword arguments.
        self.invoke()
        for call in self.system.call_args_list:
            self.assertEqual(len(call.args), 1)
            self.assertEqual(call.kwargs, {})
            self.assertIs(type(call.args[0]), str)

    def test_callback_returns_none(self):
        self.assertIsNone(self.call_callback())
        self.assertEqual(self.events, [
            ('system', EXTRACT_CMD),
            ('system', UPDATE_CMD),
            ('remove', 'messages.pot'),
        ])

    def test_command_metadata(self):
        self.assertEqual(cli.update.name, 'update')
        self.assertEqual(cli.update.help, 'Update all languages.')
        self.assertEqual(cli.update.params, [])
        self.assertIs(cli.translate.commands['update'], cli.update)

    def test_help_output(self):
        result = self.invoke('--help')
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output,
                         'Usage: app translate update [OPTIONS]\n'
                         '\n'
                         '  Update all languages.\n'
                         '\n'
                         'Options:\n'
                         '  --help  Show this message and exit.\n')
        self.assertEqual(self.events, [])

    def test_extra_argument_is_usage_error_and_runs_nothing(self):
        result = self.invoke('en')
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Got unexpected extra argument (en)", result.output)
        self.assertEqual(self.events, [])

    # --- error paths -----------------------------------------------------

    def test_extract_failure_raises_and_stops(self):
        self.system_results = [1]
        result = self.invoke()
        self.assertEqual(result.exit_code, 1)
        self.assertIsInstance(result.exception, RuntimeError)
        self.assertEqual(str(result.exception), 'extract command failed')
        self.assertEqual(result.exception.args, ('extract command failed',))
        self.assertEqual(result.output, '')
        self.assertEqual(self.events, [('system', EXTRACT_CMD)])
        self.remove.assert_not_called()

    def test_update_failure_raises_and_skips_remove(self):
        self.system_results = [0, 1]
        result = self.invoke()
        self.assertEqual(result.exit_code, 1)
        self.assertIsInstance(result.exception, RuntimeError)
        self.assertEqual(result.exception.args, ('update command failed',))
        self.assertEqual(result.output, '')
        # Current behaviour that looks like a bug: when `pybabel update`
        # fails, the freshly extracted messages.pot is never removed and is
        # left behind in the working directory.
        self.assertEqual(self.events, [
            ('system', EXTRACT_CMD),
            ('system', UPDATE_CMD),
        ])
        self.remove.assert_not_called()

    def test_failure_is_raw_runtime_error_not_click_exception(self):
        # Current behaviour that looks like a bug: failures surface as an
        # uncaught RuntimeError (traceback, exit code 1) rather than a
        # click.ClickException with a clean error message.
        self.system_results = [1]
        with self.assertRaises(RuntimeError) as cm:
            self.call_callback()
        self.assertEqual(str(cm.exception), 'extract command failed')
        self.system_results = [0, 1]
        with self.assertRaises(RuntimeError) as cm:
            self.call_callback()
        self.assertEqual(str(cm.exception), 'update command failed')

    def test_any_nonzero_status_is_failure(self):
        # os.system returns a wait status on POSIX (e.g. 256 for exit 1,
        # 32512 for "command not found"); any truthy value counts as failure.
        for status in (1, 2, 127, 256, 32512, -1):
            with self.subTest(stage='extract', status=status):
                self.events.clear()
                self.system_results = [status]
                result = self.invoke()
                self.assertEqual(result.exit_code, 1)
                self.assertEqual(str(result.exception),
                                 'extract command failed')
                self.assertEqual(self.events, [('system', EXTRACT_CMD)])
            with self.subTest(stage='update', status=status):
                self.events.clear()
                self.system_results = [0, status]
                result = self.invoke()
                self.assertEqual(result.exit_code, 1)
                self.assertEqual(str(result.exception),
                                 'update command failed')
                self.assertEqual(self.events, [('system', EXTRACT_CMD),
                                               ('system', UPDATE_CMD)])
        self.remove.assert_not_called()

    def test_remove_error_propagates(self):
        # Success of both pybabel steps is not checked against the file
        # actually existing; a missing messages.pot surfaces as the raw
        # FileNotFoundError from os.remove.
        self.remove.side_effect = FileNotFoundError(
            2, 'No such file or directory')
        result = self.invoke()
        self.assertEqual(result.exit_code, 1)
        self.assertIsInstance(result.exception, FileNotFoundError)
        self.assertEqual(self.system.call_args_list,
                         [mock.call(EXTRACT_CMD), mock.call(UPDATE_CMD)])
        self.remove.assert_called_once_with('messages.pot')

    def test_paths_are_relative_to_cwd(self):
        # Current behaviour that looks like a bug: babel.cfg, messages.pot,
        # app/translations and the `pybabel` executable are all resolved
        # relative to the current working directory / PATH, not to the app
        # root, so the command only works when run from the repo root.
        self.invoke()
        self.assertTrue(EXTRACT_CMD.startswith('pybabel '))
        self.assertTrue(UPDATE_CMD.startswith('pybabel '))
        self.assertNotIn(self.app.root_path, EXTRACT_CMD)
        self.assertNotIn(self.app.root_path, UPDATE_CMD)
        self.remove.assert_called_once_with('messages.pot')


if __name__ == '__main__':
    unittest.main(verbosity=2)
