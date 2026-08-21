"""AD Sync / Entra Connect commands, split by resource area. Each sibling
module registers its commands on the shared `sync_app` (see _shared.py) via
the `@sync_app.command(...)` decorator — importing them here for their side
effects is what actually wires the commands up."""

from ._shared import sync_app
from . import (
    extract,
)
