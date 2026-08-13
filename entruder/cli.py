import typer
from entruder.modules.enum import enum_app
from entruder.modules.login import login_app
from entruder.globals import CACHE_DIR,SESSIONS_DIR 

app = typer.Typer(
    name = "entruder",
    help = "Azure/Entra ID testing toolkit",
    no_args_is_help=True
)

# Initializing modules
app.add_typer(enum_app,name="enum")
app.add_typer(login_app,name="login")

# initializing the cache directory
CACHE_DIR.mkdir(mode=0o700, exist_ok=True)
SESSIONS_DIR.mkdir(mode=0o700, exist_ok=True)