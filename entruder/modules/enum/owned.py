import typer

from entruder.globals import API_VERSIONS
from entruder.utils import (
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session, graph_collect


def _annotate_owned(obj, relationship):
    """Tag a directoryObject with its short type, how the user relates to it, and
    the escalation primitive it exposes  so the dangerous rows stand out."""
    otype = (obj.get("@odata.type", "") or "").split(".")[-1] or "unknown"
    obj["_type"] = otype
    obj["_relationship"] = relationship

    if otype == "directoryRole":
        escalation = "directory-role"                # a role the user already holds
    elif relationship == "owner" and otype in ("servicePrincipal", "application"):
        escalation = "own->add-cred"                 # add a secret/cert, auth as the principal
    elif relationship == "owner" and otype == "group" and obj.get("isAssignableToRole"):
        escalation = "role-assignable->self-add"     # add self, inherit the group's role
    else:
        escalation = "-"
    obj["_escalation"] = escalation
    return obj


@enum_app.command("owned")
@handle_cli_errors
def enum_owned(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    control: bool = typer.Option(True, "-control/-no-control",
        help="Also include groups and directory roles the user inherits via "
             "transitive membership (default on)"),
    output: OutputFormat = output_option(),
):
    """Enumerate everything the current user owns (objects they can modify to escalate) or controls via membership, the escalation blast radius of this identity."""
    tenant, headers = prepare_session(tenant, client_id, "graph")
    graph = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    objects = [
        _annotate_owned(obj, "owner")
        for obj in graph_collect(f"{graph}/me/ownedObjects", headers, delegated=True)
    ]
    if control:
        objects += [
            _annotate_owned(obj, "transitive-mbr")
            for obj in graph_collect(f"{graph}/me/transitiveMemberOf", headers, delegated=True)
        ]

    render(console, f"Owned & controlled by current user in {tenant}", columns.OWNED,
           objects, output=output, xml_root_tag="owned", xml_item_tag="object")
    if output == OutputFormat.table:
        risky = sum(1 for o in objects if o["_escalation"] != "-")
        console.print(f"[bold]{len(objects)}[/] objects total "
                      f"([bold red]{risky}[/] with an escalation path)")
