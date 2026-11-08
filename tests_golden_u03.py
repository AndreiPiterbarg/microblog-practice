#!/usr/bin/env python
"""Golden (characterization) tests for U03: app/cli.py `compile`
(`flask translate compile`).

These pin the CURRENT behaviour of the command, including quirks, so that a
fix for ruff S605/S607 (C08/C09) can be checked for zero behaviour change.
All process execution is mocked at the `os.system` boundary.
"""
import builtins
import unittest
from unittest import mock

import click

from app import create_app, db
from app import cli as cli_module
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


COMPILE_CMD = 'pybabel compile -d app/translations'


class TranslateCompileGoldenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.runner = self.app.test_cli_runner()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def invoke(self, args, system_rc=0):
        with mock.patch('app.cli.os.system', return_value=system_rc) as sys_, \
                mock.patch('app.cli.os.remove') as remove, \
                mock.patch('app.cli.subprocess', create=True) as subproc:
            result = self.runner.invoke(args=args)
        return result, sys_, remove, subproc

    # --- registration / discovery -----------------------------------------

    def test_registered_as_top_level_translate_group(self):
        # cli_group=None puts `translate` directly on `flask`, not under `cli`
        self.assertIn('translate', self.app.cli.commands)
        self.assertNotIn('cli', self.app.cli.commands)
        group = self.app.cli.commands['translate']
        self.assertIsInstance(group, click.Group)
        self.assertEqual(sorted(group.commands), ['compile', 'init', 'update'])
        self.assertIs(group.commands['compile'], cli_module.compile)

    def test_command_object_shape(self):
        cmd = cli_module.compile
        self.assertIsInstance(cmd, click.Command)
        self.assertEqual(cmd.name, 'compile')
        self.assertEqual(cmd.help, 'Compile all languages.')
        self.assertEqual(cmd.params, [])

    def test_compile_shadows_builtin_in_module_namespace(self):
        # Current behaviour that looks like a bug: the module-level name
        # `compile` shadows the Python builtin inside app/cli.py.
        self.assertIsNot(cli_module.compile, builtins.compile)
        self.assertIsInstance(cli_module.compile, click.Command)

    def test_help_output(self):
        result, sys_, _, _ = self.invoke(['translate', 'compile', '--help'])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(
            result.output,
            'Usage: app translate compile [OPTIONS]\n'
            '\n'
            '  Compile all languages.\n'
            '\n'
            'Options:\n'
            '  --help  Show this message and exit.\n')
        sys_.assert_not_called()

    def test_listed_in_translate_group_help(self):
        result, sys_, _, _ = self.invoke(['translate', '--help'])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('  compile  Compile all languages.\n', result.output)
        sys_.assert_not_called()

    # --- success path -----------------------------------------------------

    def test_success_runs_exact_shell_command_once(self):
        result, sys_, remove, subproc = self.invoke(['translate', 'compile'])
        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.exception)
        self.assertEqual(result.output, '')
        self.assertIsNone(result.return_value)
        # Current behaviour flagged by S605/S607: a single shell string with
        # a bare (PATH-resolved) `pybabel` and a CWD-relative directory.
        sys_.assert_called_once_with(COMPILE_CMD)
        self.assertEqual(sys_.call_args.args, (COMPILE_CMD,))
        self.assertEqual(sys_.call_args.kwargs, {})
        remove.assert_not_called()
        self.assertEqual(subproc.mock_calls, [])

    def test_success_does_not_run_extract(self):
        _, sys_, _, _ = self.invoke(['translate', 'compile'])
        self.assertEqual(sys_.call_args_list, [mock.call(COMPILE_CMD)])
        for c in sys_.call_args_list:
            self.assertNotIn('extract', c.args[0])

    def test_callback_direct_call_returns_none(self):
        # The callback is wrapped by Flask's with_appcontext, so it needs an
        # active click context.
        with mock.patch('app.cli.os.system', return_value=0) as sys_, \
                click.Context(cli_module.compile):
            self.assertIsNone(cli_module.compile.callback())
        sys_.assert_called_once_with(COMPILE_CMD)

    def test_command_string_is_not_cwd_or_app_root_aware(self):
        # Current behaviour that looks like a bug: the path is relative to
        # the process CWD, not app.root_path, and is identical regardless of
        # where the app lives.
        self.app.root_path = '/somewhere/else/app'
        _, sys_, _, _ = self.invoke(['translate', 'compile'])
        sys_.assert_called_once_with('pybabel compile -d app/translations')

    def test_callback_without_click_context_raises_before_running(self):
        with mock.patch('app.cli.os.system', return_value=0) as sys_:
            with self.assertRaisesRegex(RuntimeError,
                                        r'^There is no active click context\.$'):
                cli_module.compile.callback()
        sys_.assert_not_called()

    # --- failure paths ----------------------------------------------------

    def assert_failed(self, result, sys_):
        self.assertEqual(result.exit_code, 1)
        self.assertIsInstance(result.exception, RuntimeError)
        self.assertIs(type(result.exception), RuntimeError)
        self.assertEqual(result.exception.args, ('compile command failed',))
        self.assertEqual(str(result.exception), 'compile command failed')
        # Not a ClickException, so click prints nothing; error is raised.
        self.assertEqual(result.output, '')
        sys_.assert_called_once_with(COMPILE_CMD)

    def test_nonzero_exit_status_raises_runtime_error(self):
        # os.system on POSIX returns a wait status (exit code 1 -> 256)
        result, sys_, remove, _ = self.invoke(['translate', 'compile'], 256)
        self.assert_failed(result, sys_)
        remove.assert_not_called()

    def test_return_value_1_raises(self):
        result, sys_, _, _ = self.invoke(['translate', 'compile'], 1)
        self.assert_failed(result, sys_)

    def test_command_not_found_status_raises(self):
        # shell "command not found" -> exit 127 -> wait status 127 << 8
        result, sys_, _, _ = self.invoke(['translate', 'compile'], 127 << 8)
        self.assert_failed(result, sys_)

    def test_negative_return_value_raises(self):
        # Current behaviour that looks like a bug: any truthy value counts
        # as failure; the status is never decoded or reported.
        result, sys_, _, _ = self.invoke(['translate', 'compile'], -1)
        self.assert_failed(result, sys_)

    def test_signal_status_raises_same_generic_error(self):
        # Current behaviour that looks like a bug: killed-by-signal (status 9)
        # yields the same message, with no exit code/signal detail.
        result, sys_, _, _ = self.invoke(['translate', 'compile'], 9)
        self.assert_failed(result, sys_)

    def test_failure_propagates_when_not_caught(self):
        with mock.patch('app.cli.os.system', return_value=256) as sys_:
            with self.assertRaises(RuntimeError) as ctx:
                self.runner.invoke(args=['translate', 'compile'],
                                   catch_exceptions=False)
        self.assertEqual(str(ctx.exception), 'compile command failed')
        sys_.assert_called_once_with(COMPILE_CMD)

    def test_callback_direct_call_raises_on_failure(self):
        with mock.patch('app.cli.os.system', return_value=256), \
                click.Context(cli_module.compile):
            with self.assertRaisesRegex(RuntimeError,
                                        r'^compile command failed$'):
                cli_module.compile.callback()

    def test_os_system_exception_propagates_unchanged(self):
        with mock.patch('app.cli.os.system',
                        side_effect=OSError('boom')) as sys_:
            result = self.runner.invoke(args=['translate', 'compile'])
        self.assertEqual(result.exit_code, 1)
        self.assertIs(type(result.exception), OSError)
        self.assertEqual(str(result.exception), 'boom')
        sys_.assert_called_once_with(COMPILE_CMD)

    # --- argument handling ------------------------------------------------

    def test_extra_argument_rejected_without_running(self):
        result, sys_, _, _ = self.invoke(['translate', 'compile', 'de'])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Error: Got unexpected extra argument (de)",
                      result.output)
        sys_.assert_not_called()

    def test_unknown_option_rejected_without_running(self):
        result, sys_, _, _ = self.invoke(
            ['translate', 'compile', '-d', 'other'])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Error: No such option: -d", result.output)
        sys_.assert_not_called()

    def test_shell_metacharacters_cannot_reach_command(self):
        # No user input flows into the shell string.
        result, sys_, _, _ = self.invoke(
            ['translate', 'compile', '; rm -rf /'])
        self.assertEqual(result.exit_code, 2)
        sys_.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
