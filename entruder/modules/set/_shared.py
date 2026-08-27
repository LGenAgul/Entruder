import typer

from entruder.columns import Columns
from entruder.console import CONSOLE as console
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


set_app = typer.Typer(help="Modify or add an objects/users attributes", no_args_is_help=True)
columns = Columns()
