"""Enumeration commands, split by resource area. Each sibling module registers
its commands on the shared `enum_app` (see _shared.py) via the
`@enum_app.command(...)` decorator — importing them here for their side
effects is what actually wires the commands up."""

from ._shared import enum_app
from . import (
    serviceprincipals,
    applications,
    owned,
    subscriptions,
    storage,
    keyvault,
    webapps,
    conditionalaccess,
    roles,
    devices,
    consents,
    automation,
    au,
    privileges,
    users,
    groups,
)
