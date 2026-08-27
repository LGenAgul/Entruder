import typer

from entruder.columns import Columns
from entruder.console import CONSOLE as console

azsync_app = typer.Typer(help="AD Sync / Entra Connect exploitation modules", no_args_is_help=True)
columns = Columns()
