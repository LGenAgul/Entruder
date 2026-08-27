import typer

from entruder.columns import Columns
from entruder.console import CONSOLE as console
from entruder.globals import (
    resource_group_from_id,
    prepare_session,
    graph_collect,
    resolve_principal_names,
    resolve_app_roles,
    DEFAULT_APP_ROLE,
)


enum_app = typer.Typer(help="Enumeration Module for discovering directory objects and users", no_args_is_help=True)
columns = Columns()
