import typer
from rich.console import Console

from entruder.columns import Columns
from entruder.utils import parse_error

brute_app = typer.Typer(help="Brute-force / guessing commands (credentials, User-Agents, resource names)", no_args_is_help=True)
console = Console()
columns = Columns()


def classify_ropc_result(result: dict) -> tuple:
    """
    Bucket a ROPC (grant_type=password) response into a sweep outcome.
    Shared by `brute mfasweep` and `brute uasweep` so both commands react to
    lockouts and fatal errors the same way rather than drifting apart.
    Returns (status, message):
      gap_no_mfa        - authenticated, no MFA challenge at all
      gap_unenrolled     - MFA required but the user never enrolled
      expected_mfa       - MFA required (expected, not a gap)
      expected_ca        - blocked by Conditional Access (expected, not a gap)
      fatal_wrong_password / fatal_account_missing - stop the whole sweep
      locked              - account locked; caller decides whether to continue
      other               - anything else, non-fatal
    """
    if "access_token" in result:
        return "gap_no_mfa", "authenticated with no MFA challenge"

    description = result.get("error_description", "")

    if "AADSTS50079" in description:
        return "gap_unenrolled", "MFA required but user never enrolled"

    if "AADSTS50076" in description:
        return "expected_mfa", "MFA required (expected)"

    if "AADSTS53003" in description or "AADSTS50105" in description:
        return "expected_ca", "blocked by Conditional Access (expected)"

    if "AADSTS50126" in description:
        return "fatal_wrong_password", parse_error(description)

    if "AADSTS50034" in description:
        return "fatal_account_missing", parse_error(description)

    if "AADSTS50053" in description:
        return "locked", parse_error(description)

    return "other", parse_error(description or result.get("error", "Unknown error"))
