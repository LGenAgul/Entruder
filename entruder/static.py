from pathlib import Path

class State:
    verbose: bool = False
    no_progress: bool = False

STATE = State()

PLANES = {
    "management": "https://management.azure.com/.default",
    "graph":       "https://graph.microsoft.com/.default",
    "storage":     "https://storage.azure.com/.default",
    "keyvault":    "https://vault.azure.net/.default",  # Key Vault's resource id is vault.azure.net, not .com
}

RESOURCE_SHORTCUTS = {
    "graph":      "https://graph.microsoft.com/",
    "management": "https://management.azure.com/",
    "storage":    "https://storage.azure.com/",
    "keyvault":   "https://vault.azure.net/",
}

# resources swept by `login mfasweep` — broader than RESOURCE_SHORTCUTS since
# Conditional Access MFA enforcement is evaluated per resource/client pairing,
# not uniformly per identity, so more resources means more chances to find a gap
MFA_SWEEP_RESOURCES = {
    "graph":      "https://graph.microsoft.com/",
    "management": "https://management.azure.com/",
    "keyvault":   "https://vault.azure.net/",
    "azuregraph": "https://graph.windows.net/",
    "outlook":    "https://outlook.office365.com/",
}

CACHE_DIR  = Path.home() / ".entruder"
SESSIONS_DIR = CACHE_DIR / "sessions"
DOMAINS_FILE = CACHE_DIR / "domains.json"
ACTIVE_FILE = CACHE_DIR / "active.json"

# Default timeout (seconds) for all outbound HTTP requests
HTTP_TIMEOUT = 30
EXPIRY_BUFFER = 120


API_VERSIONS = {
    "management":    "2022-01-01",
    "storage":       "2026-04-01",
    "storage_data":  "2021-08-06",  # x-ms-version for the Blob Service data-plane REST API (List Containers/Blobs)
    "graph":         "v1.0",
    "keyvault":      "7.4",
    "authorization": "2022-04-01",  # Microsoft.Authorization/permissions (effective-permissions self-check)
    "authorization_pim": "2020-10-01-preview",  # Microsoft.Authorization/roleEligibilityScheduleInstances — PIM is still preview-only in ARM
    "web":           "2022-09-01",  # Microsoft.Web/sites (App Service)
    "automation":    "2023-11-01",  # Microsoft.Automation/automationAccounts
}

# --- Microsoft Graph request config ------------------------------------------
# $select field lists and headers used by the enum commands. Keep each field
# list next to its matching $select string so they don't drift apart.

BASIC_FIELDS = ["id", "displayName", "userPrincipalName", "accountEnabled", "jobTitle", "department", "customSecurityAttributes"]
BASIC_PARAMS = {"$select": "id,displayName,userPrincipalName,accountEnabled,jobTitle,department,customSecurityAttributes"}

TRANSITIVE_PARAMS = {"$select": "id,displayName,description,securityEnabled,isAssignableToRole,roleTemplateId"}

GROUP_PARAMS = {"$select": "id,displayName,description,securityEnabled,isAssignableToRole,mailEnabled,groupTypes"}

SP_PARAMS = {"$select": "id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,"
                        "appRoleAssignmentRequired,publisherName,homepage,replyUrls,tags,keyCredentials,passwordCredentials"}

# Microsoft's own "home" tenant for its first-party service principals (Graph,
# Exchange Online, Teams, etc.) — every tenant carries ~200-300 of these by
# default. appOwnerOrganizationId == this ID is the standard way to tell them
# apart from tenant-created or third-party-consented service principals.
MS_FIRST_PARTY_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
# @odata.type can't be explicitly $selected — Graph rejects it with a 400 on
# a polymorphic collection like /me/ownedObjects. It's included automatically
# regardless, so the same SP_PARAMS work unchanged for both endpoints.

APP_PARAMS = {"$select": "id,appId,displayName,signInAudience,web,spa,publicClient,isFallbackPublicClient,"
                         "requiredResourceAccess,keyCredentials,passwordCredentials,tags"}

FULL_METADATA_ACCEPT = "application/json;odata.metadata=full"

# fields kept when projecting transitiveMemberOf entries down to groups / rolesA
GROUP_FIELDS = {"id", "displayName", "description", "securityEnabled", "isAssignableToRole", "@odata.type"}
ROLE_FIELDS = {"id", "displayName", "description", "roleTemplateId", "@odata.type"}

ERROR_CODES = {
    "AADSTS50076":   "MFA required, try login device for interactive flow",
    "AADSTS50079":   "MFA registration required",
    "AADSTS50126":   "Invalid username or password",
    "AADSTS7000215": "Invalid client secret",
    "AADSTS50001":   "Invalid resource URI",
    "AADSTS70011":   "Invalid scope",
    "AADSTS53003":   "Conditional Access policy blocked sign-in",
    "AADSTS50105":   "User not assigned to the app / blocked by Conditional Access",
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

# Microsoft Graph service principal ID is the same across all tenants
MSGRAPH_SP_ID = "00000003-0000-0000-c000-000000000002"

# Common high-value app role IDs on MS Graph
MSGRAPH_APP_ROLES = {
    "Mail.ReadWrite.All":           "e2a3a72e-5f79-4c64-b1b1-878b674786c9",
    "Files.ReadWrite.All":          "75359482-378d-4052-8f01-80520e7db3cd",
    "Directory.ReadWrite.All":      "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
    "RoleManagement.ReadWrite.All": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
    "User.ReadWrite.All":           "741f803b-c850-494e-b5df-cde7c675a1ca",
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


# User-Agent strings swept by `login uasweep` — Conditional Access policies
# can scope MFA/grant controls to a device platform or client app, and that
# targeting is read off the User-Agent header ROPC sends, so different UAs
# can land in different CA branches for the same account. "default" sends no
# override (entruder/httpx's own UA); "empty" sends the header with no value.
USER_AGENT_SWEEP = {
    "default":         None,
    "empty":           "",
    "windows_edge":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "macos_safari":    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "linux_firefox":   "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "android_chrome":  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "ios_safari":      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "outlook_ios":     "Outlook-iOS/1.0",
    "outlook_android": "Outlook-Android/2.0",
    "teams_android":   "Teams-Android/1.0",
    "onedrive_ios":    "OneDrive-iOS/1.0",
    "powershell":      "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1",
    "playstation":     "Mozilla/5.0 (PlayStation 5 3.03/SmartTV) AppleWebKit/605.1.15 (KHTML, like Gecko"
}

# Container names `brute blobs` tries against every --account given, probing
# each for anonymous List Blobs access (the "Container" public access level).
STORAGE_CONTAINER_GUESSES = [
    "$web", "data", "backup", "backups", "files", "public", "assets", "static",
    "media", "logs", "uploads", "images", "documents", "docs", "reports",
    "exports", "archive", "config", "configs", "secrets", "private", "internal",
    "test", "dev", "prod", "www", "content", "storage",
]

MFA_EXCLUSION_PATTERNS = [
    "mfa", "no-mfa", "nomfa", "yolo", "exclude", "bypass", "exempt"
]

# Entra ID built-in directory role "template IDs" — these GUIDs are constant
# across every tenant (unlike a role *assignment* id, which is per-tenant),
# so a token's `wids` claim can be matched against them directly to name and
# tier the directory roles the token holder currently has active. Not
# exhaustive — covers the roles most relevant to privilege escalation and
# lateral movement during an assessment.
# Source: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
DIRECTORY_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": {"name": "Global Administrator",               "tier": "critical"},
    "e8611ab8-c189-46e8-94e1-60213ab1f814": {"name": "Privileged Role Administrator",       "tier": "critical"},
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": {"name": "Privileged Authentication Administrator", "tier": "critical"},
    "fe930be7-5e62-47db-91af-98c3a49a38b1": {"name": "User Administrator",                  "tier": "high"},
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": {"name": "Application Administrator",           "tier": "high"},
    "158c047a-c907-4556-b7ef-446551a6b5f7": {"name": "Cloud Application Administrator",     "tier": "high"},
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": {"name": "Authentication Administrator",        "tier": "high"},
    "194ae4cb-b126-40b2-bd5b-6091b380977d": {"name": "Security Administrator",              "tier": "high"},
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": {"name": "Conditional Access Administrator",    "tier": "high"},
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": {"name": "Partner Tier2 Support",                "tier": "high"},
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": {"name": "Groups Administrator",                "tier": "medium"},
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": {"name": "Helpdesk Administrator",              "tier": "medium"},
    "29232cdf-9323-42fd-ade2-1d097af3e4de": {"name": "Exchange Administrator",              "tier": "medium"},
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": {"name": "SharePoint Administrator",            "tier": "medium"},
    "3a2c62db-5318-420d-8d74-23affee5d9d5": {"name": "Intune Administrator",                "tier": "medium"},
    "9360feb5-f418-4baa-8175-e2a00bac4301": {"name": "Directory Writers",                   "tier": "medium"},
    "4ba39ca4-527c-499a-b93d-d9b492c50246": {"name": "Partner Tier1 Support",               "tier": "medium"},
    "88d8e3e3-8f55-4a1e-953a-9b9898b8876b": {"name": "Directory Readers",                   "tier": "low"},
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451": {"name": "Global Reader",                       "tier": "low"},
}

DIRECTORY_ROLE_TIER_ORDER = ["critical", "high", "medium", "low"]