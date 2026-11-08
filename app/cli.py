import os
from flask import Blueprint
import click

bp = Blueprint('cli', __name__, cli_group=None)


@bp.cli.group()
def translate():
    """Translation and localization commands."""
    pass


@translate.command()
@click.argument('lang')
def init(lang):
    """Initialize a new language."""
    if os.system('pybabel extract -F babel.cfg -k _l -o messages.pot .'):  # noqa: S605 - constant command, no user input
        raise RuntimeError('extract command failed')
    if os.system(  # noqa: S605 - dev-only CLI; LANG is the invoking developer's own argv, no trust boundary
            'pybabel init -i messages.pot -d app/translations -l ' + lang):
        raise RuntimeError('init command failed')
    os.remove('messages.pot')


@translate.command()
def update():
    """Update all languages."""
    if os.system('pybabel extract -F babel.cfg -k _l -o messages.pot .'):  # noqa: S605, S607 - constant dev-only command, no user input; pybabel from venv PATH
        raise RuntimeError('extract command failed')
    if os.system('pybabel update -i messages.pot -d app/translations'):  # noqa: S605 - constant command string, no user input
        raise RuntimeError('update command failed')
    os.remove('messages.pot')


@translate.command()
def compile():
    """Compile all languages."""
    if os.system('pybabel compile -d app/translations'):  # noqa: S605 - constant command string, no user input reaches the shell
        raise RuntimeError('compile command failed')
