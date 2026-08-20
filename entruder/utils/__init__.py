from .http import request_json
from .logging import vprint, report_error, handle_cli_errors, iter_with_progress, iter_futures_with_progress
from .auth import (
    build_cert_credential,
    build_msal_http_client,
    device_login_v1,
    device_login_v2,
    auth_code_login,
    acquire_for_resources,
    refresh_access_token,
)
from .parser import (
    parse_error,
    parse_xml_tag,
    decode_jwt,
    decode_jwt_header,
    parse_token,
    csv_to_list,
    resolve_resource,
    resolve_plane_from_resource,
    resolve_plane_from_scope,
)
from .tenant import (
    require_tenant,
    save_domain_mapping,
)
from .session import (
    save_session,
    get_session,
    require_session,
    initialize_tenant_cache,
    get_tenant_cache,
    require_tenant_cache,
    )
from .output import (render
                     , OutputFormat
                     , pluck
                     , format_groups
                     , format_mfa
                     , format_credentials
                     , format_custom_attributes
                     , format_role_assignments
                     , format_app_role_assignments
                     , format_directory_role_eligibilities
                     , format_azure_role_eligibilities
                     , format_storage_keys
                     , format_access_policies
                     , format_string_list
                     , format_dict_summary
                     , format_brute_containers
                     ,
                     output_option)
