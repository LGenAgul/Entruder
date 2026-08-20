"""Basic tenant/identity info commands, split out of `enum` since they're
low-privilege context-gathering (unauthenticated tenant lookup, whoami-style
privilege check, subscription/user/group listings) rather than resource-type
enumeration. Each sibling module registers its commands on the shared
`info_app` (see _shared.py) via the `@info_app.command(...)` decorator —
importing them here for their side effects is what actually wires the
commands up."""

from ._shared import info_app
from . import (
    tenant,
    privileges,
    subscriptions,
    users,
    groups,
)
