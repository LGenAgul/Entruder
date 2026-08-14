from pathlib import Path

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

CLIENT_IDS = {
    "azure_cli":    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "azure_portal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
    "teams":        "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
}

CACHE_DIR  = Path.home() / ".entruder"
SESSIONS_DIR = CACHE_DIR / "sessions"

API_VERSIONS = {
    "management": "2022-01-01",
    "storage":    "2023-01-01",
    "graph":      "v1.0",
    "keyvault":   "7.4",
}