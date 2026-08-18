import typer
from entruder.modules.enum import enum_app
from entruder.modules.login import login_app
from entruder.modules.analyze import analyze_app
from entruder.globals import CACHE_DIR,SESSIONS_DIR,STATE

app = typer.Typer(
    name = "entruder",
    help = "Azure/Entra ID testing toolkit",
    no_args_is_help=True
)

@app.callback()
def main(
    verbose: bool = typer.Option(False, "-verbose", "-v", help="Show full tracebacks for internal errors")
):
    """Global options applied to every command."""
    STATE.verbose = verbose

# verbosity


# Initializing modules
app.add_typer(enum_app,name="enum")
app.add_typer(login_app,name="login")
app.add_typer(analyze_app,name="analyze")

# initializing the cache directory
CACHE_DIR.mkdir(mode=0o700, exist_ok=True)
SESSIONS_DIR.mkdir(mode=0o700, exist_ok=True)

