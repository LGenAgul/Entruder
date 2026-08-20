"""Login commands, split by auth flow. Each sibling module registers its
commands on the shared `login_app` (see _shared.py) via the
`@login_app.command(...)` decorator — importing them here for their side
effects is what actually wires the commands up."""

from ._shared import login_app
from . import (
    secret,
    ropc,
    device,
    refresh,
    cert,
    foci,
    kerberos,
    authcode,
    mfasweep,
    uasweep,
    token,
)
