import typer
from entruder.modules.enum import enum_app
app = typer.Typer(
    name = "entruder",
    help = "Azure/Entra ID testing toolkit",
    no_args_is_help=True
)

# Initializing modules
app.add_typer(enum_app,name="enum")