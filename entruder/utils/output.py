import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from enum import Enum
from xml.dom import minidom

from rich.table import Table


class OutputFormat(str, Enum):
    table = "table"
    csv = "csv"
    json = "json"
    xml = "xml"


def render(console, title: str, columns: list, records: list, output: OutputFormat = OutputFormat.table, xml_item_tag: str = "item") -> None:
    """
    Generic result renderer shared by every enum command. `columns` is an
    ordered list of (label, key) tuples describing which fields to show in the
    human-readable formats and what to call them; `records` is the raw list of
    dicts as returned by the API (e.g. Graph objects).

    table/csv use the column labels for a readable summary — that's the
    "global default" view, same shape `enum users` already had. json/xml dump
    the full raw records (every field the API returned, not just the selected
    columns) so nothing is lost for tooling further down the pipeline.
    """
    if output == OutputFormat.table:
        if not records:
            console.print("[bold yellow][*][/] No results")
            return
        _render_table(console, title, columns, records)
    elif output == OutputFormat.csv:
        _render_csv(console, columns, records)
    elif output == OutputFormat.json:
        _render_json(console, records)
    elif output == OutputFormat.xml:
        _render_xml(console, title, xml_item_tag, records)


def _render_table(console, title, columns, records) -> None:
    table = Table(title=title)
    for label, _ in columns:
        table.add_column(label)
    for r in records:
        table.add_row(*(_cell(r.get(key)) for _, key in columns))
    console.print(table)


def _render_csv(console, columns, records) -> None:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([label for label, _ in columns])
    for r in records:
        writer.writerow([_cell(r.get(key)) for _, key in columns])
    console.print(buf.getvalue(), end="")


def _render_json(console, records) -> None:
    console.print(json.dumps(records, indent=2, default=str))


def _render_xml(console, root_tag, item_tag, records) -> None:
    root = ET.Element(_xml_safe_tag(root_tag))
    for r in records:
        item = ET.SubElement(root, item_tag)
        for key, value in r.items():
            field = ET.SubElement(item, _xml_safe_tag(key))
            field.text = "" if value is None else str(value)
    pretty = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
    console.print(pretty, end="")


def _cell(value) -> str:
    return "N/A" if value is None else str(value)


def _xml_safe_tag(name: str) -> str:
    """XML element names can't start with a digit or contain spaces/symbols — sanitize."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    if not safe or safe[0].isdigit():
        safe = f"_{safe}"
    return safe
