import typer
from rich.console import Console

from entruder.columns import Columns
from entruder.globals import (
    resource_group_from_id,
    prepare_session,
    graph_collect,
    resolve_principal_names,
    resolve_app_roles,
    resolve_app_role_id,
    resolve_user_id,
    resolve_group_id,
    resolve_role_id,
    DEFAULT_APP_ROLE,
)


set_app = typer.Typer(help="Enumeration", no_args_is_help=True)
console = Console()
columns = Columns()
