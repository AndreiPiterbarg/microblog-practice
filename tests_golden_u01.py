#!/usr/bin/env python
"""Golden (characterization) tests for U01: app/cli.py init
(`flask translate init LANG`).

These pin the CURRENT behaviour of the unit, including quirks. They must
pass identically before and after any security fix. All process/file side
effects are patched at the boundary (os.system, os.remove).
"""
import unittest
from unittest import mock

import click

from app import cli, create_app, db
from config import Config

EXTRACT_CMD = 'pybabel extract -F babel.cfg -k _l -o messages.pot .'
INIT_PREFIX = 'pybabel init -i messages.pot -d app/translations -l '


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


class TranslateInitGoldenCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.runner = self.app.test_cli_runner()

        self.manager = mock.Mock()
        system_patcher = mock.patch('app.cli.os.system', return_value=0)
        remove_patcher = mock.patch('app.cli.os.remove', return_value=None)
        self.system = system_patcher.start()
        self.remove = remove_patcher.start()
        self.addCleanup(system_patcher.stop)
        self.addCleanup(remove_patcher.stop)
        self.manager.attach_mock(self.system, 'system')
        self.manager.attach_mock(self.remove, 'remove')

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def invoke(self, *args):
        return self.runner.invoke(args=['translate', 'init', *args])

    def call_callback(self, lang):
        # init.callback is wrapped by Flask's with_appcontext, which needs an
        # active click context.
        with click.Context(cli.init):
            return cli.init.callback(lang)

    # --- registration / metadata -------------------------------------

    def test_command_registered_under_translate_group(self):
        self.assertIs(self.app.cli.commands['translate'], cli.translate)
        self.assertIs(cli.translate.commands['init'], cli.init)
        self.assertEqual(cli.init.name, 'init')
        self.assertEqual(cli.init.help, 'Initialize a new language.')
        self.assertEqual([p.name for p in cli.init.params], ['lang'])
        self.assertTrue(cli.init.params[0].required)
        self.assertEqual(cli.init.params[0].nargs, 1)

    def test_help_output(self):
        result = self.invoke('--help')
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(
            result.output,
            'Usage: app translate init [OPTIONS] LANG\n'
            '\n'
            '  Initialize a new language.\n'
            '\n'
            'Options:\n'
            '  --help  Show this message and exit.\n')
        self.system.assert_not_called()
        self.remove.assert_not_called()

    # --- normal path -------------------------------------------------

    def test_success_runs_extract_init_remove_in_order(self):
        result = self.invoke('es')
        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.exception)
        self.assertEqual(result.output, '')
        self.assertEqual(self.manager.mock_calls, [
            mock.call.system(EXTRACT_CMD),
            mock.call.system(
                'pybabel init -i messages.pot -d app/translations -l es'),
            mock.call.remove('messages.pot'),
        ])

    def test_callback_returns_none(self):
        self.assertIsNone(self.call_callback('fr'))
        self.assertEqual(self.system.call_args_list, [
            mock.call(EXTRACT_CMD),
            mock.call(INIT_PREFIX + 'fr'),
        ])
        self.remove.assert_called_once_with('messages.pot')

    def test_commands_are_single_shell_strings(self):
        # os.system is called with one positional str, no kwargs
        self.invoke('de')
        for c in self.system.call_args_list:
            self.assertEqual(len(c.args), 1)
            self.assertIsInstance(c.args[0], str)
            self.assertEqual(c.kwargs, {})

    # --- error paths -------------------------------------------------

    def test_extract_failure_raises_and_stops(self):
        self.system.return_value = 1
        result = self.invoke('es')
        self.assertEqual(result.exit_code, 1)
        self.assertIsInstance(result.exception, RuntimeError)
        self.assertEqual(str(result.exception), 'extract command failed')
        self.assertEqual(result.output, '')
        self.assertEqual(self.manager.mock_calls,
                         [mock.call.system(EXTRACT_CMD)])

    def test_extract_failure_via_callback(self):
        self.system.return_value = 1
        with self.assertRaises(RuntimeError) as cm:
            self.call_callback('es')
        self.assertEqual(cm.exception.args, ('extract command failed',))
        self.remove.assert_not_called()

    def test_init_failure_raises_and_skips_remove(self):
        self.system.side_effect = [0, 1]
        result = self.invoke('es')
        self.assertEqual(result.exit_code, 1)
        self.assertIsInstance(result.exception, RuntimeError)
        self.assertEqual(str(result.exception), 'init command failed')
        # Current behaviour that looks like a bug: on init failure the
        # extracted messages.pot is left behind (os.remove never runs).
        self.assertEqual(self.manager.mock_calls, [
            mock.call.system(EXTRACT_CMD),
            mock.call.system(INIT_PREFIX + 'es'),
        ])

    def test_any_truthy_status_is_failure(self):
        # os.system returns a wait status (e.g. 256 for exit 1, -1 on error)
        for status in (256, -1, 32512):
            self.system.reset_mock()
            self.system.side_effect = None
            self.system.return_value = status
            with self.assertRaises(RuntimeError) as cm:
                self.call_callback('es')
            self.assertEqual(str(cm.exception), 'extract command failed')
            self.system.side_effect = [0, status]
            with self.assertRaises(RuntimeError) as cm:
                self.call_callback('es')
            self.assertEqual(str(cm.exception), 'init command failed')
        self.remove.assert_not_called()

    def test_remove_error_propagates(self):
        self.remove.side_effect = FileNotFoundError(2, 'No such file')
        result = self.invoke('es')
        self.assertEqual(result.exit_code, 1)
        self.assertIsInstance(result.exception, FileNotFoundError)
        self.assertEqual(self.system.call_count, 2)
        self.remove.assert_called_once_with('messages.pot')

    def test_missing_lang_is_usage_error(self):
        result = self.invoke()
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Error: Missing argument 'LANG'.", result.output)
        self.system.assert_not_called()
        self.remove.assert_not_called()

    def test_extra_argument_is_usage_error(self):
        result = self.invoke('es', 'fr')
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Error: Got unexpected extra argument (fr)",
                      result.output)
        self.system.assert_not_called()

    # --- quirks ------------------------------------------------------

    def test_lang_is_concatenated_unquoted_into_shell(self):
        # Current behaviour that looks like a bug (C03 shell injection):
        # LANG is appended verbatim to a shell command string, so shell
        # metacharacters are passed straight to the shell.
        payload = 'es; touch /tmp/pwned && echo $HOME'
        result = self.invoke(payload)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(self.system.call_args_list, [
            mock.call(EXTRACT_CMD),
            mock.call(INIT_PREFIX + payload),
        ])

    def test_lang_with_space_becomes_multiple_shell_words(self):
        # Current behaviour that looks like a bug: a single LANG argument
        # containing a space is split by the shell into several words.
        self.invoke('es fr')
        self.assertEqual(self.system.call_args_list[1],
                         mock.call(INIT_PREFIX + 'es fr'))

    def test_empty_lang_accepted(self):
        # Current behaviour that looks like a bug: empty LANG is not
        # validated; command ends with a dangling '-l '.
        result = self.invoke('')
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(self.system.call_args_list[1],
                         mock.call('pybabel init -i messages.pot '
                                   '-d app/translations -l '))
        self.remove.assert_called_once_with('messages.pot')

    def test_lang_not_validated_or_normalised(self):
        # Current behaviour: no validation/normalisation of LANG.
        for lang in ('EN_us', '../../etc', 'pt-BR', 'zz'):
            self.system.reset_mock()
            result = self.invoke(lang)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(self.system.call_args_list[1],
                             mock.call(INIT_PREFIX + lang))

    def test_relative_paths_and_bare_executable(self):
        # Current behaviour (C02): bare 'pybabel' resolved via PATH and all
        # paths are relative to the process CWD.
        self.invoke('es')
        cmds = [c.args[0] for c in self.system.call_args_list]
        self.assertTrue(all(c.startswith('pybabel ') for c in cmds))
        self.remove.assert_called_once_with('messages.pot')


if __name__ == '__main__':
    unittest.main(verbosity=2)
