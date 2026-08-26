import json
import re


def save_domain_mapping(domain: str, tenant: str) -> None:
    from entruder.static import DOMAINS_FILE, CACHE_DIR
    CACHE_DIR.mkdir(mode=0o700, exist_ok=True)
    domains = {}
    if DOMAINS_FILE.exists():
         domains = json.loads(DOMAINS_FILE.read_text())
    domains[domain] = tenant
    DOMAINS_FILE.write_text(json.dumps(domains, indent=2))
    DOMAINS_FILE.chmod(0o600)


def is_domain(value: str) -> bool:
    if not value:
        return False
    return bool(re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$').match(value))


def resolve_tenant_from_domain(tenant: str):
    # skip resolving if not a domain
    if not is_domain(tenant):
         return tenant

    from entruder.static import DOMAINS_FILE
    if not DOMAINS_FILE.exists():
        return None

    domains = json.loads(DOMAINS_FILE.read_text())
    mapped_tenant=domains.get(tenant)
    if mapped_tenant:
         return mapped_tenant
    # domain not found thus we return nothing for the app to quit
    return None


def require_tenant(tenant: str, console):
     import typer
     if not tenant:
        console.print("[bold red][-][/] No --tenant provided and no active session found")
        console.print("[dim] Pass --tenant explicitly, or run a login command first to set an active session[/dim]")
        raise typer.Exit(1)
     resolved_tenant = resolve_tenant_from_domain(tenant)
     if not resolved_tenant:
        console.print(f"[bold red][-][/] Could not resolve {tenant} to a known tenant")
        console.print(f"[bold][-][/] To resolve a domain to a tenant and store it in cache do: entruder enum tenant --domain <DOMAIN>")
        raise typer.Exit(1)
     return resolved_tenant
