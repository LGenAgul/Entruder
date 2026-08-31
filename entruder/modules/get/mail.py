import typer

from entruder.static import API_VERSIONS
from entruder.utils import (
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import get_app, console, columns, prepare_session, graph_get


@get_app.command("mail")
@handle_cli_errors
def get_mail(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    upn: str = typer.Option(None, "-u", "--upn", help="Mailbox owner's userPrincipalName/email (Optional, default: 'me', the signed-in user on a delegated token)"),
    message_id: str = typer.Option(None, "-i", "--message-id", help="Specific message id to fetch (Optional, default: the most recent message in the mailbox)"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Fetch a single email message's full content (subject, sender, recipients, body, attachments) via Microsoft Graph. Defaults to the most recent message in the mailbox (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    base = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/{'me' if not upn else f'users/{upn}'}"
    select = "id,subject,from,toRecipients,ccRecipients,receivedDateTime,sentDateTime,hasAttachments,importance,isRead,body"

    if message_id:
        message = graph_get(headers, f"{base}/messages/{message_id}", params={"$select": select})
    else:
        result = graph_get(headers, f"{base}/messages",
                            params={"$select": select, "$top": 1, "$orderby": "receivedDateTime desc"})
        messages = result.get("value", []) if isinstance(result, dict) else []
        if not messages:
            console.print("[bold red][-][/] No messages found in this mailbox")
            raise typer.Exit(1)
        message = messages[0]

    attachments = []
    if message.get("hasAttachments"):
        att_result = graph_get(headers, f"{base}/messages/{message['id']}/attachments",
                                params={"$select": "id,name,contentType,size"})
        attachments = att_result.get("value", []) if isinstance(att_result, dict) else []

    body = message.get("body", {}) or {}
    row = {
        "id":          message.get("id"),
        "subject":     message.get("subject"),
        "from":        ((message.get("from") or {}).get("emailAddress") or {}).get("address"),
        "to":          [((r.get("emailAddress") or {}).get("address")) for r in message.get("toRecipients") or []],
        "cc":          [((r.get("emailAddress") or {}).get("address")) for r in message.get("ccRecipients") or []],
        "received":    message.get("receivedDateTime"),
        "sent":        message.get("sentDateTime"),
        "importance":  message.get("importance"),
        "is_read":     message.get("isRead"),
        "body_type":   body.get("contentType"),
        "body":        body.get("content"),
        "attachments": [f"{a.get('name')} ({a.get('contentType')}, {a.get('size')} bytes)" for a in attachments],
    }

    render(console, f"Mail for {upn or 'me'}", columns.MAIL, row, output=output, xml_item_tag="message")
