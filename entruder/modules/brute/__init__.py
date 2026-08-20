"""Brute-force/guessing commands, split out on their own since they're a
different shape of operation from `login`/`enum`/`info` — many attempts
against a target namespace (passwords x resources x clients, User-Agents,
storage account names) rather than a single authenticated call. Each sibling
module registers its commands on the shared `brute_app` (see _shared.py) via
the `@brute_app.command(...)` decorator — importing them here for their side
effects is what actually wires the commands up."""

from ._shared import brute_app
from . import (
    mfasweep,
    uasweep,
    blobs,
)
