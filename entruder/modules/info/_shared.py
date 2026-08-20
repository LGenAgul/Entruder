import typer
from rich.console import Console

from entruder.columns import Columns
from entruder.globals import (
    resource_group_from_id,
    prepare_session,
    graph_collect,
    resolve_principal_names,
    resolve_app_roles,
    DEFAULT_APP_ROLE,
)


info_app = typer.Typer(help="Basic tenant/identity context (whoami, subs, tenant lookup, directory listings)", no_args_is_help=True)
console = Console()
columns = Columns()
