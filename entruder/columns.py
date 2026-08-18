

from entruder.utils import (
    pluck,
    format_mfa,
    format_groups,
    format_credentials,
    format_custom_attributes,
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
        ("App Roles", "app_roles", pluck("resourceDisplayName")),
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