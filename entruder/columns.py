

from entruder.utils import (
    pluck,
    format_mfa,
    format_groups,
    format_credentials,
    format_custom_attributes,
    format_role_assignments,
    format_app_role_assignments,
    format_directory_role_eligibilities,
    format_azure_role_eligibilities,
    format_storage_keys,
    format_access_policies,
    format_string_list,
    format_dict_summary,
    )


class Columns:

    SUBSCRIPTION = [
        ("Id", "id"),
        ("Authorization Source", "authorizationSource"),
        ("Managed by these Tenants", "managedByTenants"),
        ("Tenant Id", "tenantId"),
        ("displayName", "displayName"),
        ("State", "state"),
        ("Subscription Policies", "subscriptionPolicies"),
    ]

    USER = [
        ("Display Name", "displayName"),
        ("UPN", "userPrincipalName"),
        ("Enabled", "accountEnabled"),
        ("Job Title", "jobTitle"),
        ("Department", "department"),
        ("Custom Security Attributes", "customSecurityAttributes", format_custom_attributes),
    ]

    GROUP = [
        ("Group Id",    "id"),
        ("Display Name",    "displayName"),
        ("Description",     "description"),
        ("Security",        "securityEnabled"),
        ("Role-Assignable", "isAssignableToRole"),
        ("Mail Enabled",    "mailEnabled"),
        ("Types",           "groupTypes"),
    ]

    SP = [
        ("Display Name",         "displayName"),
        ("App Id",               "appId"),
        ("Type",                 "servicePrincipalType"),
        ("Enabled",              "accountEnabled"),
        ("Assignment Required",  "appRoleAssignmentRequired"),
        ("Owner Org",            "appOwnerOrganizationId"),
        ("Publisher",            "publisherName"),
        ("Homepage",             "homepage"),
        ("Cert Creds",           "keyCredentials", format_credentials),
        ("Secret Creds",         "passwordCredentials", format_credentials),
        ("Tags",                 "tags"),
    ]

    # requiredResourceAccess is resolved into a flat list of readable
    # "Resource: permission (Scope/Role)" lines by _resolve_required_resource_access
    # before rendering — see modules/enum/applications.py.
    APPLICATION = [
        ("Display Name",         "displayName"),
        ("App Id",               "appId"),
        ("Sign-in Audience",     "signInAudience"),
        ("Redirect URIs",        "_redirect_uris", format_string_list),
        ("Public Client",        "_public_client"),
        ("Required Permissions", "_required_resource_access", format_string_list),
        ("Cert Creds",           "keyCredentials", format_credentials),
        ("Secret Creds",         "passwordCredentials", format_credentials),
        ("Tags",                 "tags"),
    ]



    USERINFO = [
        ("Display Name", "displayName"),
        ("UPN", "userPrincipalName"),
        ("Enabled", "accountEnabled"),
        ("Job Title", "jobTitle"),
        ("Department", "department"),
        ("Custom Security Attributes", "customSecurityAttributes", format_custom_attributes),
        ("Groups", "groups", format_groups),
        ("Roles", "roles", pluck("displayName")),
        ("MFA", "mfa", format_mfa),
        ("Owned", "owned", pluck("displayName")),
        ("App Roles", "app_roles", format_app_role_assignments),
        ("MFA Exclusion Groups", "mfa_exclusion_groups"),
    ]


    TENANT = [
        ("Domain",          "domain"),
        ("Tenant ID",       "tenant_id"),
        ("Token Endpoint",  "token_endpoint"),
        ("Tenant Region",   "tenant_region"),
        ("MsGraph Host",    "msgraph_host"),
        ("Namespace",       "namespace"),
        ("Brand Name",      "brand_name"),
        ("Cloud",           "cloud"),
        ("Auth URL",        "auth_url"),
        ("DSSO Enabled",    "dsso_enabled"),
        ("Federated",       "federated"),
    ]

    RESOURCE = [
        ("Id", "id"),
        ("Name", "name"),
        ("Type", "type"),
        ("Kind", "kind"),
        ("Location", "location"),
        ("Tags", "tags")
    ]

    # _type / _relationship / _escalation are synthesized by enum_owned; the raw
    # directoryObject supplies id + displayName.
    OWNED = [
        ("Type",         "_type"),
        ("Display Name", "displayName"),
        ("Id",           "id"),
        ("Relationship", "_relationship"),
        ("Escalation",   "_escalation"),
    ]

    STORAGE = [
    ("Name",           "name"),
    ("Resource Group", "resource_group"),
    ("Location",       "location"),
    ("Kind",           "kind"),
    ("SKU",            "sku"),
    ("Able to list keys",     "shared_key"),     
    ("Public Blobs",   "public_access"),  
    ("Public Network", "public_network"), 
    ("Network ACL",    "network_default"),
    ("HTTPS Only",     "https_only"),
    ("Min TLS",        "min_tls"),
    ("OAuth Default",  "oauth_default"),
    ("Blob Endpoint",  "blob_endpoint"),
    ("Created",        "created"),
    ("RBAC: List Keys",  "can_list_keys"),
    ("Can List Containers", "can_list_containers"),
    ("Access Keys",     "keys", format_storage_keys),
]

    WEBAPP = [
        ("Name",               "name"),
        ("Resource Group",     "resource_group"),
        ("Location",           "location"),
        ("Kind",               "kind"),
        ("State",              "state"),
        ("Default Hostname",   "default_hostname"),
        ("HTTPS Only",         "https_only"),
        ("Client Cert",        "client_cert_enabled"),
        ("Public Network",     "public_network"),
        ("Managed Identity",   "identity", format_dict_summary),
        ("Min TLS",            "min_tls"),
        ("FTPS State",         "ftps_state"),
        ("Remote Debugging",   "remote_debugging"),
        ("Always On",          "always_on"),
        ("Slots",              "slots", format_string_list),
        ("App Settings",       "app_settings", format_dict_summary),
        ("Connection Strings", "connection_strings", format_dict_summary),
        ("Publishing Creds",   "publishing_credentials", format_dict_summary),
    ]

    VAULT = [
        ("Name",              "name"),
        ("Resource Group",    "resource_group"),
        ("Location",          "location"),
        ("Vault Uri",         "vault_uri"),
        ("SKU",               "sku"),
        ("RBAC Authorization", "rbac_authorization"),
        ("Access Policies",   "access_policies", format_access_policies),
        ("Soft Delete",       "soft_delete"),
        ("Purge Protection",  "purge_protection"),
        ("Public Network",    "public_network"),
        ("Network ACL",       "network_default"),
        ("Can List Secrets",  "can_list_secrets"),
    ]

    SECRET = [
        ("Name",         "name"),
        ("Enabled",      "enabled"),
        ("Content Type", "contentType"),
        ("Created",      "created"),
        ("Updated",      "updated"),
        ("Expires",      "expires"),
        ("Tags",         "tags"),
    ]

    KEY = [
        ("Name",    "name"),
        ("Enabled", "enabled"),
        ("Created", "created"),
        ("Updated", "updated"),
        ("Expires", "expires"),
        ("Tags",    "tags"),
    ]

    CERTIFICATE = [
        ("Name",       "name"),
        ("Enabled",    "enabled"),
        ("Thumbprint", "thumbprint"),
        ("Created",    "created"),
        ("Updated",    "updated"),
        ("Expires",    "expires"),
        ("Tags",       "tags"),
    ]

    SECRETVALUE = [
        ("Name",         "name"),
        ("Value",        "value"),
        ("Content Type", "contentType"),
        ("Version",      "version"),
        ("Enabled",      "enabled"),
        ("Expires",      "expires"),
    ]

    CONTAINER = [
        ("Name",                 "Name"),
        ("Public Access",        "PublicAccess"),
        ("Last Modified",        "Last-Modified"),
        ("Lease Status",         "LeaseStatus"),
        ("Lease State",          "LeaseState"),
        ("Immutability Policy",  "HasImmutabilityPolicy"),
        ("Legal Hold",           "HasLegalHold"),
    ]

    BLOB = [
        ("Name",          "Name"),
        ("Content Type",  "Content-Type"),
        ("Size (bytes)",  "Content-Length"),
        ("Last Modified", "Last-Modified"),
        ("Blob Type",     "BlobType"),
        ("Access Tier",   "AccessTier"),
        ("Lease Status",  "LeaseStatus"),
        ("Etag",          "Etag"),
    ]

    # roles/administrative_units/owned/app_role_assignments come from /me's
    # transitive membership + ownership; azure_role_assignments is the ARM
    # roleAssignments properties blob for the same principal on -subid.
    PRIV = [
        ("Display Name",          "displayName"),
        ("UPN",                   "userPrincipalName"),
        ("Object Id",             "id"),
        ("Groups",                "groups", format_groups),
        ("Directory Roles",       "directory_roles", pluck("displayName")),
        ("Eligible Directory Roles (PIM)", "eligible_directory_roles", format_directory_role_eligibilities),
        ("Administrative Units",  "administrative_units", pluck("displayName")),
        ("Owned Objects",         "owned", pluck("displayName")),
        ("App Role Assignments",  "app_role_assignments", format_app_role_assignments),
        ("Azure Role Assignments", "azure_role_assignments", format_role_assignments),
        ("Eligible Azure Roles (PIM)", "eligible_azure_role_assignments", format_azure_role_eligibilities),
    ]

    # users/groups/roles are resolved to readable names by _project_ca_policy
    # before rendering — see modules/enum/conditionalaccess.py.
    CAPOLICY = [
        ("Name",              "displayName"),
        ("State",             "state"),
        ("Users",             "users", format_dict_summary),
        ("Applications",      "applications", format_dict_summary),
        ("Conditions",        "conditions_extra", format_dict_summary),
        ("Grant Controls",    "grant_controls", format_dict_summary),
        ("Session Controls",  "session_controls", format_dict_summary),
        ("Modified",          "modifiedDateTime"),
    ]

    AUTOMATION_ACCOUNT = [
        ("Name",                   "name"),
        ("Resource Group",         "resource_group"),
        ("Location",               "location"),
        ("State",                  "state"),
        ("SKU",                    "sku"),
        ("Public Network",         "public_network"),
        ("Local Auth Disabled",    "disable_local_auth"),
        ("Identity Type",          "identity_type"),
        ("Identity Principal Id",  "identity_principal_id"),
        ("Created",                "created"),
    ]

    RUNBOOK = [
        ("Name",          "name"),
        ("Type",          "runbook_type"),
        ("State",         "state"),
        ("Log Verbose",   "log_verbose"),
        ("Log Progress",  "log_progress"),
        ("Description",   "description"),
        ("Created",       "created"),
        ("Last Modified", "last_modified"),
    ]

    RUNBOOK_CONTENT = [
        ("Name",    "name"),
        ("Content", "content"),
    ]

    AUTOMATION_VARIABLE = [
        ("Name",          "name"),
        ("Encrypted",     "encrypted"),
        ("Value",         "value"),
        ("Description",   "description"),
        ("Created",       "created"),
        ("Last Modified", "last_modified"),
    ]

    CONSENT = [
        ("Client App",   "clientAppName"),
        ("Client SP Id", "clientId"),
        ("Resource App", "resourceAppName"),
        ("Resource SP Id", "resourceId"),
        ("Consent Type", "consentType"),
        ("Principal",    "principalName"),
        ("Scopes",       "scopes", format_string_list),
    ]

    DEVICE = [
        ("Display Name", "displayName"),
        ("Device Id",    "deviceId"),
        ("OS",           "operatingSystem"),
        ("OS Version",   "operatingSystemVersion"),
        ("Trust Type",   "trustType"),
        ("Ownership",    "deviceOwnership"),
        ("Enabled",      "accountEnabled"),
        ("Compliant",    "isCompliant"),
        ("Managed",      "isManaged"),
        ("MDM App Id",   "mdmAppId"),
        ("Registered",   "registrationDateTime"),
        ("Last Sign-In", "approximateLastSignInDateTime"),
        ("Owners",       "registeredOwners", pluck("userPrincipalName")),
        ("Owner Roles",  "ownerRoles", format_string_list),
    ]

    ROLE = [
        ("Role Name",       "roleName"),
        ("Principal",       "principalName"),
        ("Principal Id",    "principalId"),
        ("Directory Scope", "directoryScopeId"),
        ("App Scope",       "appScopeId"),
    ]

    TOKEN = [
        ("Plane",                 "plane"),
        ("Identity Type",         "identity_type"),
        ("UPN",                   "upn"),
        ("Name",                  "name"),
        ("Object Id",             "object_id"),
        ("App Id",                "app_id"),
        ("App Display Name",      "app_display_name"),
        ("Tenant Id",             "tenant_id"),
        ("Audience",              "audience"),
        ("Directory Roles",       "directory_roles"),
        ("Highest Privilege",     "highest_role_tier"),
        ("Delegated Scopes",      "delegated_scopes"),
        ("App Permissions",       "app_permissions"),
        ("MFA Performed",         "mfa_performed"),
        ("Auth Methods (amr)",    "auth_methods"),
        ("FOCI Client",           "is_foci_client"),
        ("FOCI Hint",             "foci_hint"),
        ("Issued At",             "issued_at"),
        ("Not Before",            "not_before"),
        ("Expires At",            "expires_at"),
        ("Expired",               "expired"),
        ("Token Version",         "token_version"),
        ("Signing Alg",           "signing_alg"),
        ("Key Id",                "key_id"),
    ]