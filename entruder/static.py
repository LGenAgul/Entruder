from pathlib import Path

class State:
    verbose: bool = False
    no_progress: bool = False

STATE = State()

# Typer renders the app's `help=` text through Click's help formatter, which
# rewraps a plain paragraph onto one line — a leading "\b" is Click's signal
# to leave the paragraph's line breaks alone, which is what keeps the ASCII
# art intact instead of getting flattened into a single reflowed line.
BANNER = "\b" + r"""
 Made in Georgia
 ███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗██████╗ ███████╗██████╗
 ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██╔════╝██╔══██╗
 █████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██║  ██║█████╗  ██████╔╝
 ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║  ██║██╔══╝  ██╔══██╗
 ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██████╔╝███████╗██║  ██║
 ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
 Слава Україні
"""



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
    # was mislabeled "power_automate" — 27922004-... is Outlook Mobile's client id
    "outlook_mobile":   "27922004-5251-4030-b22d-91ecd9a37ea4",
    "microsoft_edge":   "ecd6b820-32c2-49b6-98a6-444530e5a77a",
}

# Client ID -> friendly app name for well-known Microsoft first-party public
# clients (source: GraphRunner's Invoke-BruteClientIDAccess $AppInfo table).
# Broader than FOCI_CLIENTS (which is keyed by name for the small subset that
# are actually redeemable via `login foci`) — this is for identifying/labeling
# an arbitrary client_id/appid seen in a token or session, the same way
# DIRECTORY_ROLES resolves a wid to a name in `analyze token`.
KNOWN_CLIENT_IDS = {
    "00b41c95-dab0-4487-9791-b9d2c32c80f2": "Office 365 Management",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
    "0ec893e0-5785-4de6-99da-4ed124e5296c": "Office UWP PWA",
    "18fbca16-2224-45f6-85b0-f7bf2b39b3f3": "Microsoft Docs",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
    "1b3c667f-cde3-4090-b60b-3d2abd0117f0": "Windows Spotlight",
    "1b730954-1685-4b74-9bfd-dac224a7b894": "Azure Active Directory PowerShell",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
    "22098786-6e16-43cc-a27d-191a01a1e3b5": "Microsoft To-Do client",
    "268761a2-03f3-40df-8a8b-c3db24145b6b": "Universal Store Native Client",
    "26a7ee05-5602-4d76-a7ba-eae8b7b67941": "Windows Search",
    "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
    "29d9ed98-a469-4536-ade2-f981bc1d605e": "Microsoft Authentication Broker",
    "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8": "Microsoft Bing Search for Microsoft Edge",
    "4813382a-8fa7-425e-ab75-3b753aab3abb": "Microsoft Authenticator App",
    "4e291c71-d680-4d0e-9640-0a3358e31177": "PowerApps",
    "57336123-6e14-4acc-8dcf-287b6088aa28": "Microsoft Whiteboard Client",
    "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0": "Microsoft Flow Mobile PROD-GCCH-CN",
    "60c8bde5-3167-4f92-8fdb-059f6176dc0f": "Enterprise Roaming and Backup",
    "66375f6b-983f-4c2c-9701-d680650f588f": "Microsoft Planner",
    "844cca35-0656-46ce-b636-13f48b0eecbd": "Microsoft Stream Mobile Native",
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1": "Visual Studio - Legacy",
    "87749df4-7ccf-48f8-aa87-704bad0e0e16": "Microsoft Teams - Device Admin Agent",
    "90f610bf-206d-4950-b61d-37fa6fd1b224": "Aadrm Admin PowerShell",
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223": "Microsoft Intune Company Portal",
    "9bc3ab49-b65d-410a-85ad-de819febfddc": "Microsoft SharePoint Online Management Shell",
    "a0c73c16-a7e3-4564-9a95-2bdf47383716": "Microsoft Exchange Online Remote PowerShell",
    "a40d7d7d-59aa-447e-a655-679a4107e548": "Accounts Control UI",
    "a569458c-7f2b-45cb-bab9-b7dee514d112": "Yammer iPhone",
    "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive Sync Engine",
    "af124e86-4e96-495a-b70a-90f90ab96707": "OneDrive iOS App",
    "b26aadf8-566f-4478-926f-589f601d9c74": "OneDrive",
    "b90d5b8f-5503-4153-b545-b31cecfaece2": "AADJ CSP",
    "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12": "Microsoft Power BI",
    "c58637bb-e2e1-4312-8a00-04b5ffcd3403": "SharePoint Online Client Extensibility",
    "cb1056e2-e479-49de-ae31-7812af012ed8": "Microsoft Azure Active Directory Connect",
    "cf36b471-5b44-428c-9ce7-313bf84528de": "Microsoft Bing Search",
    "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0": "SharePoint",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
    "e9b154d0-7658-433b-bb25-6b8e0a8a7c59": "Outlook Lite",
    "e9c51622-460d-4d3d-952d-966a5b1da34c": "Microsoft Edge",
    "eb539595-3fe1-474e-9c1d-feb3625d1be5": "Microsoft Tunnel",
    "ecd6b820-32c2-49b6-98a6-444530e5a77a": "Microsoft Edge",
    "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d": "SharePoint Android",
    "f448d7e5-e313-4f90-a3eb-5dbb3277e4b3": "Media Recording for Dynamics 365 Sales",
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34": "Microsoft Edge",
    "fb78d390-0c51-40cd-8e17-fdbfab77341b": "Microsoft Exchange REST API Based PowerShell",
    "fc0f3af4-6835-4174-b806-f7db311fd2f3": "Microsoft Intune Windows Agent",
}

# Short name -> client id, resolved by `resolve_client_id()` so any --client-id
# option accepts these instead of the raw GUID (e.g. --client-id officemanagement).
# Covers the rest of KNOWN_CLIENT_IDS that FOCI_CLIENTS doesn't already name;
# a few entries here (azurecli, azurepowershell, outlookmobile, edge,
# microsoftoffice) are deliberate no-underscore/alternate-spelling duplicates
# of a FOCI_CLIENTS entry pointing at the same id, kept as convenience aliases.
# Three ids all display as bare "Microsoft Edge" in Microsoft's own naming with
# no further distinction available — edge is the one already known via
# FOCI_CLIENTS as microsoft_edge, edge2/edge3 are the other two.
CLIENT_ID_ALIASES = {
    "officemanagement":        "00b41c95-dab0-4487-9791-b9d2c32c80f2",
    "azurecli":                "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "uwppwa":                  "0ec893e0-5785-4de6-99da-4ed124e5296c",
    "msdocs":                  "18fbca16-2224-45f6-85b0-f7bf2b39b3f3",
    "azurepowershell":         "1950a258-227b-4e31-a9cf-717495945fc2",
    "spotlight":               "1b3c667f-cde3-4090-b60b-3d2abd0117f0",
    "aadpowershell":           "1b730954-1685-4b74-9bfd-dac224a7b894",
    "todo":                    "22098786-6e16-43cc-a27d-191a01a1e3b5",
    "universalstore":          "268761a2-03f3-40df-8a8b-c3db24145b6b",
    "windowssearch":           "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
    "outlookmobile":           "27922004-5251-4030-b22d-91ecd9a37ea4",
    "authenticationbroker":    "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "bingsearchedge":          "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8",
    "authenticator":           "4813382a-8fa7-425e-ab75-3b753aab3abb",
    "powerapps":               "4e291c71-d680-4d0e-9640-0a3358e31177",
    "whiteboard":              "57336123-6e14-4acc-8dcf-287b6088aa28",
    "flowmobile":              "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0",
    "roamingbackup":           "60c8bde5-3167-4f92-8fdb-059f6176dc0f",
    "planner":                 "66375f6b-983f-4c2c-9701-d680650f588f",
    "streammobile":            "844cca35-0656-46ce-b636-13f48b0eecbd",
    "visualstudio":            "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",
    "teamsdeviceadmin":        "87749df4-7ccf-48f8-aa87-704bad0e0e16",
    "aadrmpowershell":         "90f610bf-206d-4950-b61d-37fa6fd1b224",
    "intuneportal":            "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
    "spomanagementshell":      "9bc3ab49-b65d-410a-85ad-de819febfddc",
    "exchangeonlinepowershell": "a0c73c16-a7e3-4564-9a95-2bdf47383716",
    "accountscontrolui":       "a40d7d7d-59aa-447e-a655-679a4107e548",
    "yammeriphone":            "a569458c-7f2b-45cb-bab9-b7dee514d112",
    "onedriveios":             "af124e86-4e96-495a-b70a-90f90ab96707",
    "onedriveclient":          "b26aadf8-566f-4478-926f-589f601d9c74",
    "aadjcsp":                 "b90d5b8f-5503-4153-b545-b31cecfaece2",
    "powerbi":                 "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12",
    "spoclientext":            "c58637bb-e2e1-4312-8a00-04b5ffcd3403",
    "aadconnect":              "cb1056e2-e479-49de-ae31-7812af012ed8",
    "bingsearch":              "cf36b471-5b44-428c-9ce7-313bf84528de",
    "sharepoint":              "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",
    "microsoftoffice":         "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "outlooklite":             "e9b154d0-7658-433b-bb25-6b8e0a8a7c59",
    "edge2":                   "e9c51622-460d-4d3d-952d-966a5b1da34c",
    "tunnel":                  "eb539595-3fe1-474e-9c1d-feb3625d1be5",
    "edge":                    "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "sharepointandroid":       "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d",
    "dynamicsmediarecording":  "f448d7e5-e313-4f90-a3eb-5dbb3277e4b3",
    "edge3":                   "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34",
    "exchangerestpowershell":  "fb78d390-0c51-40cd-8e17-fdbfab77341b",
    "intuneagent":             "fc0f3af4-6835-4174-b806-f7db311fd2f3",
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

# Azure RBAC (ARM) built-in role definition IDs — the GUID is constant across
# every tenant/subscription (built-in roles live in the platform, not the
# tenant), so `set arm-role` can accept a friendly name and map it to the id
# without a lookup call. Keys are lowercased and space-stripped to match the
# `role.lower().replace(" ", "")` normalization at the call site. Covers the
# generic management roles plus the storage/Key Vault/compute data-plane roles
# most useful for privilege escalation and lateral movement during an
# assessment — not exhaustive; pass a raw role definition GUID for anything else.
# Source: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
WELL_KNOWN_ARM_ROLES = {
    # --- Generic management-plane ---
    "owner":                              "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "contributor":                        "b24988ac-6180-42a0-ab88-20f7382dd24c",
    "reader":                             "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "useraccessadministrator":            "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    "rolebasedaccesscontroladministrator": "f58310d9-a9f6-439a-9e8d-f62e7b41a168",
    "managedidentityoperator":            "f1a07417-d97a-45cb-824c-7a7467783830",

    # --- Storage (management + data plane) ---
    "storageaccountcontributor":          "17d1049b-9a84-46fb-8f53-869881c3d3ab",
    "storageblobdataowner":               "b7e6dc6d-f1e8-4753-8033-0f276bb0955b",
    "storageblobdatacontributor":         "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
    "storageblobdatareader":              "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
    "storagequeuedatacontributor":        "974c5e8b-45b9-4653-ba55-5f855dd0fb88",
    "storagefiledatasmbsharecontributor": "0c867c2a-1d8c-454a-a3db-ab2ea1bdc8bb",

    # --- Key Vault (data plane, RBAC-authorized vaults) ---
    "keyvaultadministrator":              "00482a5a-887f-4fb3-b363-3b7fe8e74483",
    "keyvaultsecretsofficer":             "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
    "keyvaultsecretsuser":                "4633458b-17de-408a-b874-0445c86b69e6",
    "keyvaultcertificatesofficer":        "a4417e6f-fecd-4de8-b567-7b0420556985",
    "keyvaultcryptouser":                 "12338af0-0e69-4776-bea7-57ae8d297424",

    # --- Compute / login ---
    "virtualmachinecontributor":          "9980e02c-c2be-4d73-94e8-173b1dc7cf3c",
    "virtualmachineadministratorlogin":   "1c0163c0-47e6-4577-8991-ea5c82e286e4",
    "virtualmachineuserlogin":            "fb879df8-f326-4884-b1cf-06f3ad86be52",

    # --- Networking / monitoring / platform ---
    "networkcontributor":                 "4d97b98b-1d4f-4787-a291-c67834d212e7",
    "monitoringreader":                   "43d0d8ad-25c7-4714-9337-8ba259a9fe05",
    "loganalyticscontributor":            "92aaf0da-9dab-42b6-94a3-d43ce8d16293",
    "automationcontributor":              "f353d9bd-d4a6-484e-a77a-8050b599b867",
    "websitecontributor":                 "de139f84-1756-47ae-9be6-808fbbe84772",
}