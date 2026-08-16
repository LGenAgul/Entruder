from pathlib import Path

class State:
    verbose: bool = False

STATE = State()

PLANES = {
    "management": "https://management.azure.com/.default",
    "graph":       "https://graph.microsoft.com/.default",
    "storage":     "https://storage.azure.com/.default",
    "keyvault":    "https://vault.azure.com/.default",
}

RESOURCE_SHORTCUTS = {
    "graph":      "https://graph.microsoft.com/",
    "management": "https://management.azure.com/",
    "storage":    "https://storage.azure.com/",
    "keyvault":   "https://vault.azure.com/",
}

CACHE_DIR  = Path.home() / ".entruder"
SESSIONS_DIR = CACHE_DIR / "sessions"
DOMAINS_FILE = CACHE_DIR / "domains.json"

# Default timeout (seconds) for all outbound HTTP requests
HTTP_TIMEOUT = 30
EXPIRY_BUFFER = 120


API_VERSIONS = {
    "management": "2022-01-01",
    "storage":    "2023-01-01",
    "graph":      "v1.0",
    "keyvault":   "7.4",
}

ERROR_CODES = {
    "AADSTS50076":   "MFA required, try login device for interactive flow",
    "AADSTS50079":   "MFA registration required",
    "AADSTS50126":   "Invalid username or password",
    "AADSTS7000215": "Invalid client secret",
    "AADSTS50001":   "Invalid resource URI",
    "AADSTS70011":   "Invalid scope",
    "AADSTS53003":   "Conditional Access policy blocked sign-in",
    "AADSTS65001":   "User or admin consent required",
    "AADSTS700016":  "Application not found in tenant",
    "AADSTS50034":   "User account does not exist",
    "AADSTS50057":   "User account is disabled",
    "AADSTS90002":   "Tenant not found, check the tenant ID/domain",
    "AADSTS50058":   "Silent sign-in failed — interaction required",
    "AADSTS500011":  "Resource principal not found in tenant",
    "AADSTS50053":   "Account locked from too many sign-in attempts",
    "AADSTS50055":   "Password expired",
    "AADSTS7000218": "Request missing client_assertion or client_secret",
    "AADSTS900023":  "Invalid tenant name in the request",
    "AADSTS90014":   "Missing required field in the request",
}

FOCI_CLIENTS = {
    "azure_cli":        "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "azure_powershell": "1950a258-227b-4e31-a9cf-717495945fc2",
    "teams":            "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "office":           "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "onedrive":         "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "power_automate":   "27922004-5251-4030-b22d-91ecd9a37ea4",
    "microsoft_edge":   "ecd6b820-32c2-49b6-98a6-444530e5a77a",
}


