import typer

from entruder.console import CONSOLE as console

login_app = typer.Typer(help="Various Login methods for acquiring access tokens", no_args_is_help=True)
