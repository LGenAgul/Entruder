"""Set/write commands, split by resource area. Each sibling module registers
its commands on the shared `set_app` (see _shared.py) via the
`@set_app.command(...)` decorator — importing them here for their side
effects is what actually wires the commands up."""

from ._shared import set_app
from . import (
    password,
    groupmember,
    rolemember,
    approle,
    appsecret,
    owner,
    arm_role,
)
