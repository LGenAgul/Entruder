import typer

from entruder.columns import Columns
from entruder.console import CONSOLE as console
from entruder.globals import prepare_session


sharepoint_app = typer.Typer(help="SharePoint/OneDrive enumeration and content search via the Microsoft Search API", no_args_is_help=True)
columns = Columns()
