import typer
from rich.console import Console

from entruder.columns import Columns

sync_app = typer.Typer(help="AD Sync / Entra Connect exploitation modules", no_args_is_help=True)
console = Console()
columns = Columns()
