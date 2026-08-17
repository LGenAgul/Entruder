"""Centralized output engine — shared by every command so nobody re-implements
table/csv/json/xml printing.

Adding a new command? You only need three things:

    1. Declare the columns used for the human (table/csv) views:

           FOO_COLUMNS = [
               ("Label", "dict_key"),                 # scalar field
               ("Groups", "groups", pluck("name")),   # nested list -> pick a field
           ]
       A column is (label, key) or (label, key, formatter). The formatter takes
       the raw value and returns a display string; use it for nested values.
       `pluck(field)` is a ready-made formatter for "list of dicts -> one field".

    2. Add the standard -output flag to the command signature:

           output: OutputFormat = output_option()            # defaults to table
           output: OutputFormat = output_option(OutputFormat.json)   # or json, etc.

    3. Build your body (a dict, or a list of dicts — nesting is fine) and hand it
       to render():

           render(console, title, FOO_COLUMNS, body, output=output,
                  xml_root_tag="foos", xml_item_tag="foo")

json and xml always emit the full nested body; table and csv use the columns.
That's it — no format-specific code lives in the command.
"""

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from enum import Enum
from xml.dom import minidom


class OutputFormat(str, Enum):
    table = "table"
    csv = "csv"
    json = "json"
    xml = "xml"


def output_option(default: "OutputFormat" = None, flag: str = "-output"):
    """Reusable Typer option for the -output flag, so every command exposes it
    identically. Use in a command signature:

        output: OutputFormat = output_option()                  # default: table
        output: OutputFormat = output_option(OutputFormat.json) # default: json
    """
    import typer  

    return typer.Option(
        default if default is not None else OutputFormat.table,
        flag,
        help="Output format: table, csv, json, or xml",
    )


def render(
    console,
    title: str,
    columns: list,
    data,
    output: OutputFormat = OutputFormat.table,
    xml_root_tag: str = "results",
    xml_item_tag: str = "item",
) -> None:
    """Centralized renderer.

    `data` may be a single record (dict) or a list of records (list of dicts).
    Records can contain nested dicts / lists — json and xml preserve that
    nesting in full; table and csv use `columns` and flatten nested values to
    readable strings.

    `columns` is a list of (label, key) tuples used for table/csv only.
    """
    # empty dict, empty list, or None all mean "nothing to show"
    if not data:
        console.print("[bold red][-][/] There was an error returning output")
        return

    is_list = isinstance(data, list)
    records = data if is_list else [data]

    if output == OutputFormat.json:
        _render_json(console, data)
    elif output == OutputFormat.xml:
        _render_xml(console, xml_root_tag, xml_item_tag, records, wrap_items=is_list)
    elif output == OutputFormat.csv:
        _render_csv(console, columns, records)
    else:
        _render_table(console, title, columns, records)


# --- human formats -----------------------------------------------------------

def _render_table(console, title, columns, records) -> None:
    """Simple aligned `Label : value` printout, one block per record.

    Multi-line values (e.g. a plucked list of groups) are indented so their
    continuation lines line up under the first value.
    """
    specs = [_unpack_col(c) for c in columns]
    width = max((len(label) for label, _, _ in specs), default=0)

    if title:
        console.print(title, style="bold")
    for i, r in enumerate(records):
        if i:
            console.print()  # blank line between records
        for label, key, fmt in specs:
            _print_field(console, label, _format_cell(r.get(key), fmt), width)


def _print_field(console, label, value, width) -> None:
    indent = " " * (width + 3)  # width + len(" : ")
    lines = str(value).split("\n")
    console.print(f"{label:<{width}} : {lines[0]}", markup=False, highlight=False)
    for extra in lines[1:]:
        console.print(f"{indent}{extra}", markup=False, highlight=False)


def _render_csv(console, columns, records) -> None:
    specs = [_unpack_col(c) for c in columns]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([label for label, _, _ in specs])
    for r in records:
        writer.writerow([_format_cell(r.get(key), fmt) for _, key, fmt in specs])
    console.print(buf.getvalue(), end="", markup=False, highlight=False)


# --- machine formats ---------------------------------------------------------

def _render_json(console, data) -> None:
    # dump `data` as-is so a single record stays an object and a list stays a
    # list; default=str keeps it from choking on odd types
    console.print(json.dumps(data, indent=2, default=str), markup=False, highlight=False)


def _render_xml(console, root_tag, item_tag, records, wrap_items) -> None:
    if wrap_items:
        # list of records: <root><item>..</item><item>..</item></root>
        root = ET.Element(_xml_safe_tag(root_tag))
        for r in records:
            item = ET.SubElement(root, _xml_safe_tag(item_tag))
            _value_to_xml(item, r)
    else:
        # single record: the item tag is the root, fields hang directly off it
        root = ET.Element(_xml_safe_tag(item_tag))
        _value_to_xml(root, records[0])
    pretty = minidom.parseString(ET.tostring(root, encoding="unicode")).toprettyxml(indent="  ")
    console.print(pretty, end="", markup=False, highlight=False)


def _value_to_xml(element, value) -> None:
    """Recursively attach `value` to an XML element, handling any nesting."""
    if isinstance(value, dict):
        for key, sub in value.items():
            child = ET.SubElement(element, _xml_safe_tag(key))
            _value_to_xml(child, sub)
    elif isinstance(value, (list, tuple)):
        for entry in value:
            child = ET.SubElement(element, "item")
            _value_to_xml(child, entry)
    else:
        element.text = "" if value is None else str(value)


# --- column / cell helpers ---------------------------------------------------

def _unpack_col(col):
    """A column spec is (label, key) or (label, key, formatter)."""
    if len(col) == 3:
        return col[0], col[1], col[2]
    return col[0], col[1], None


def _format_cell(value, formatter) -> str:
    """Apply a column's formatter for table/csv, or fall back to the generic
    flattener when the column has none."""
    if formatter is not None:
        return formatter(value)
    return _cell(value)


def pluck(field: str, sep: str = "\n"):
    """Formatter factory: pull `field` out of each dict in a list (or a single
    dict) and join the results. Handy for showing a compact column from a list
    of nested objects, e.g. pluck("displayName") for groups/roles."""
    def formatter(value) -> str:
        if not value:
            return ""
        items = value if isinstance(value, (list, tuple)) else [value]
        parts = []
        for item in items:
            part = item.get(field, "") if isinstance(item, dict) else item
            if part not in (None, ""):
                parts.append(str(part))
        return sep.join(parts)
    return formatter


def format_groups(value) -> str:
    """Compact group cell: name plus the security-relevant flags (whether it's a
    security group and whether it can be assigned a directory role)."""
    lines = []
    for g in value or []:
        if not isinstance(g, dict):
            lines.append(str(g))
            continue
        flags = [f"security={g.get('securityEnabled')}"]
        if g.get("isAssignableToRole"):
            flags.append("role-assignable")
        lines.append(f"{g.get('displayName', '')}  ({', '.join(flags)})")
    return "\n".join(lines)


def format_mfa(value) -> str:
    """Compact MFA cell: list the registered method types, or surface the error
    code when Graph refused the authentication/methods call."""
    if isinstance(value, dict):  # error payload (no "value" was returned)
        err = value.get("error", value)
        code = err.get("code", "denied") if isinstance(err, dict) else "denied"
        return f"error: {code}"
    methods = []
    for m in value or []:
        t = (m.get("@odata.type", "") if isinstance(m, dict) else "").split(".")[-1]
        methods.append(t.replace("AuthenticationMethod", "") or "unknown")
    return "\n".join(methods)


def format_credentials(value) -> str:
    """Compact credential cell for a servicePrincipal's keyCredentials/
    passwordCredentials: count plus the soonest expiry, so a stale/long-lived
    or about-to-lapse credential stands out at a glance."""
    if not value:
        return "0"
    expiries = sorted(v["endDateTime"] for v in value if v.get("endDateTime"))
    if not expiries:
        return str(len(value))
    return f"{len(value)} (next expiry: {expiries[0][:10]})"


def _cell(value) -> str:
    """Flatten any value (scalar, dict, or list) into a single readable string
    for table/csv cells."""
    if value is None:
        return "N/A"
    if isinstance(value, dict):
        return _flatten_dict(value)
    if isinstance(value, (list, tuple)):
        if not value:
            return ""
        # one entry per line: dicts become "k=v, k=v", scalars become str
        return "\n".join(
            _flatten_dict(v) if isinstance(v, dict) else str(v) for v in value
        )
    return str(value)


def _flatten_dict(d: dict) -> str:
    return ", ".join(f"{k}={'' if v is None else v}" for k, v in d.items())


def _xml_safe_tag(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    if not safe or safe[0].isdigit():
        safe = f"_{safe}"
    return safe
