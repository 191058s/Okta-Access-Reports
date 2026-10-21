import csv
import logging
import re
import time
from datetime import datetime
from urllib.parse import quote

import requests


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
OKTA_DOMAIN = "https://DOMAIN.okta.com"
OKTA_API_TOKEN = ""

USER_LOGINS = [
"ONE", "TWO"
]


# These groups remain in the detail CSV but are excluded from the
# common-assignment calculation and the common-assignment CSV.
IGNORED_GROUPS = {
}

IGNORE_APPLICATIONS = {
}

FAIL_ON_UNRESOLVED_USER = True

DETAIL_OUTPUT_FILE = "okta_user_assignment_details.csv"
COMMON_OUTPUT_FILE = "okta_common_assignments.csv"

LOG_FILE = "okta_common_assignments.log"

REQUEST_TIMEOUT_SECONDS = 60
MAX_RETRIES = 5


# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------

logger = logging.getLogger("okta_common_assignments")
logger.setLevel(logging.INFO)
logger.propagate = False
logger.handlers.clear()

log_formatter = logging.Formatter(
    "%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(log_formatter)

screen_handler = logging.StreamHandler()
screen_handler.setFormatter(log_formatter)

logger.addHandler(file_handler)
logger.addHandler(screen_handler)


# ----------------------------------------------------------------------
# Okta API setup
# ----------------------------------------------------------------------

OKTA_DOMAIN = OKTA_DOMAIN.rstrip("/")

session = requests.Session()
session.headers.update(
    {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json",
        "User-Agent": "Okta-Common-Assignments-Report/1.0",
    }
)


def okta_get(url, params=None, allow_404=False):
    """Perform an Okta GET request with retry and rate-limit handling."""

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(
                url,
                params=params,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            if attempt == MAX_RETRIES:
                logger.exception(
                    "Request failed after %s attempts: %s",
                    attempt,
                    url,
                )
                raise

            sleep_seconds = 2 ** (attempt - 1)
            logger.warning(
                "Request error for %s: %s. Retrying in %s seconds.",
                url,
                exc,
                sleep_seconds,
            )
            time.sleep(sleep_seconds)
            continue

        if allow_404 and response.status_code == 404:
            return response

        if response.status_code == 429:
            if attempt == MAX_RETRIES:
                logger.error(
                    "Okta rate limit remained active after %s attempts: %s",
                    attempt,
                    response.url,
                )
                response.raise_for_status()

            reset_time = int(
                response.headers.get(
                    "X-Rate-Limit-Reset",
                    int(time.time()) + 10,
                )
            )
            sleep_seconds = max(reset_time - int(time.time()), 1) + 1

            logger.warning(
                "Okta rate limit reached. Waiting %s seconds before retrying %s.",
                sleep_seconds,
                response.url,
            )
            time.sleep(sleep_seconds)
            continue

        if 500 <= response.status_code < 600:
            if attempt == MAX_RETRIES:
                logger.error(
                    "Okta returned HTTP %s after %s attempts: %s",
                    response.status_code,
                    attempt,
                    response.url,
                )
                response.raise_for_status()

            sleep_seconds = 2 ** (attempt - 1)
            logger.warning(
                "Okta returned HTTP %s for %s. Retrying in %s seconds.",
                response.status_code,
                response.url,
                sleep_seconds,
            )
            time.sleep(sleep_seconds)
            continue

        try:
            response.raise_for_status()
        except requests.HTTPError:
            logger.error("Request failed: %s", response.url)
            logger.error("Response: %s", response.text)
            raise

        return response

    raise RuntimeError(f"Request failed after retries: {url}")


def get_all_pages(url, params=None):
    """Yield all objects from an Okta cursor-paginated endpoint."""

    while url:
        response = okta_get(url, params=params)
        data = response.json()

        if not isinstance(data, list):
            raise RuntimeError(f"Expected a list from {response.url}")

        yield from data

        url = response.links.get("next", {}).get("url")
        params = None


# ----------------------------------------------------------------------
# User resolution
# ----------------------------------------------------------------------


def escape_okta_search_value(value):
    """Escape a value placed inside an Okta search expression."""

    return value.replace("\\", "\\\\").replace('"', '\\"')


def resolve_user_by_login(login):
    """Resolve an input login exactly, ignoring capitalization differences."""

    encoded_login = quote(login, safe="")
    direct_response = okta_get(
        f"{OKTA_DOMAIN}/api/v1/users/{encoded_login}",
        allow_404=True,
    )

    if direct_response.status_code == 200:
        user = direct_response.json()
        resolved_login = str(user.get("profile", {}).get("login") or "")

        if resolved_login.casefold() == login.casefold():
            logger.info(
                "Resolved login %s directly to user %s.",
                resolved_login,
                user.get("id", ""),
            )
            return user

        logger.warning(
            "Direct lookup for %s returned profile.login=%s; "
            "continuing with a case-insensitive exact search.",
            login,
            resolved_login,
        )

    escaped_login = escape_okta_search_value(login)
    search_expression = f'profile.login eq "{escaped_login}"'

    matches = list(
        get_all_pages(
            f"{OKTA_DOMAIN}/api/v1/users",
            params={
                "search": search_expression,
                "limit": 200,
            },
        )
    )

    exact_matches = [
        user
        for user in matches
        if str(user.get("profile", {}).get("login") or "").casefold() == login.casefold()
    ]

    if len(exact_matches) == 1:
        user = exact_matches[0]
        logger.info(
            "Resolved login %s to user %s.",
            exact_matches[0]["profile"]["login"],
            user.get("id", ""),
        )
        return user

    if not exact_matches:
        logger.error("No Okta user found with login: %s", login)
        return None

    matching_user_ids = ", ".join(
        str(user.get("id", ""))
        for user in exact_matches
    )
    raise RuntimeError(
        f"Multiple Okta users have profile.login={login}: "
        f"{matching_user_ids}"
    )


def normalize_input_logins(logins):
    """Trim logins, remove blanks, and reject duplicate input values."""

    normalized = []
    seen = set()

    for raw_login in logins:
        login = str(raw_login or "").strip()
        if not login:
            continue

        login_key = login.casefold()
        if login_key in seen:
            raise ValueError(f"Duplicate login in USER_LOGINS: {login}")

        seen.add(login_key)
        normalized.append(login)

    if not normalized:
        raise ValueError("USER_LOGINS does not contain any logins.")

    if len(normalized) == 1:
        logger.warning(
            "Only one user was supplied; every assignment for that user "
            "will be considered common."
        )

    return normalized


# ----------------------------------------------------------------------
# Assignment retrieval
# ----------------------------------------------------------------------


def get_user_groups(user_id):
    encoded_user_id = quote(user_id, safe="")

    return list(
        get_all_pages(
            f"{OKTA_DOMAIN}/api/v1/users/{encoded_user_id}/groups",
            params={"limit": 200},
        )
    )


def get_user_applications(user_id):
    """
    Return applications assigned to a user.

    The expanded application-user object is requested so assignment
    scope and application username can be included in the detail report.
    """

    return list(
        get_all_pages(
            f"{OKTA_DOMAIN}/api/v1/apps",
            params={
                "filter": f'user.id eq "{user_id}"',
                "expand": f"user/{user_id}",
                "limit": 200,
            },
        )
    )


def is_ignored_group(group):
    """Return True when the group's exact name is configured to be ignored."""

    group_name = str(group.get("profile", {}).get("name") or "")
    return group_name in IGNORED_GROUPS


def is_ignored_application(app):
    """Return True when the app's exact visible label is ignored."""

    app_label = str(app.get("label") or "")
    return app_label in IGNORE_APPLICATIONS


def get_application_assignment(app):
    """Return the expanded application-user assignment, when present."""

    embedded_user = app.get("_embedded", {}).get("user", {})
    return embedded_user if isinstance(embedded_user, dict) else {}


def get_application_username(assignment):
    credentials = assignment.get("credentials") or {}
    profile = assignment.get("profile") or {}

    return (
        credentials.get("userName")
        or profile.get("userName")
        or profile.get("login")
        or ""
    )


# ----------------------------------------------------------------------
# Report collection
# ----------------------------------------------------------------------


def collect_reports(users):
    detail_rows = []
    assignments_by_user = {}
    group_catalog = {}
    app_catalog = {}

    for user_number, user_record in enumerate(users, start=1):
        input_login = user_record["input_login"]
        user = user_record["user"]
        user_id = str(user.get("id") or "")
        user_profile = user.get("profile") or {}
        user_login = str(user_profile.get("login") or "")

        logger.info(
            "[%s/%s] Retrieving assignments for %s (%s).",
            user_number,
            len(users),
            input_login,
            user_id,
        )

        groups = get_user_groups(user_id)
        applications = get_user_applications(user_id)

        logger.info(
            "Retrieved %s groups and %s applications for %s.",
            len(groups),
            len(applications),
            input_login,
        )

        eligible_group_ids = set()
        eligible_app_ids = set()

        for group in groups:
            group_id = str(group.get("id") or "")
            group_profile = group.get("profile") or {}
            group_name = str(group_profile.get("name") or "")
            ignored = is_ignored_group(group)

            group_catalog[group_id] = group

            if ignored:
                logger.info(
                    "Excluded configured group from common matching: %s (%s).",
                    group_name,
                    group_id,
                )
            else:
                eligible_group_ids.add(group_id)

            detail_rows.append(
                {
                    "input_login": input_login,
                    "user_login": user_login,
                    "user_id": user_id,
                    "user_status": user.get("status", ""),
                    "user_last_login": user.get("lastLogin") or "",
                    "assignment_type": "GROUP",
                    "assignment_name": group_name,
                    "assignment_id": group_id,
                    "assignment_status": "",
                    "assignment_scope": "MEMBER",
                    "application_internal_name": "",
                    "application_username": "",
                    "group_type": group.get("type", ""),
                    "group_description": group_profile.get("description", ""),
                    "excluded_from_common_match": "YES" if ignored else "NO",
                }
            )

        for app in applications:
            app_id = str(app.get("id") or "")
            app_label = str(app.get("label") or "")
            assignment = get_application_assignment(app)
            ignored = is_ignored_application(app)

            app_catalog[app_id] = app

            if ignored:
                logger.info(
                    "Excluded configured application from common matching: "
                    "%s (%s).",
                    app_label,
                    app_id,
                )
            else:
                eligible_app_ids.add(app_id)

            detail_rows.append(
                {
                    "input_login": input_login,
                    "user_login": user_login,
                    "user_id": user_id,
                    "user_status": user.get("status", ""),
                    "user_last_login": user.get("lastLogin") or "",
                    "assignment_type": "APPLICATION",
                    "assignment_name": app_label,
                    "assignment_id": app_id,
                    "assignment_status": app.get("status", ""),
                    "assignment_scope": assignment.get("scope", ""),
                    "application_internal_name": app.get("name", ""),
                    "application_username": get_application_username(assignment),
                    "group_type": "",
                    "group_description": "",
                    "excluded_from_common_match": "YES" if ignored else "NO",
                }
            )

        assignments_by_user[user_id] = {
            "eligible_group_ids": eligible_group_ids,
            "eligible_app_ids": eligible_app_ids,
        }

    common_group_ids = set.intersection(
        *[
            assignments["eligible_group_ids"]
            for assignments in assignments_by_user.values()
        ]
    )
    common_app_ids = set.intersection(
        *[
            assignments["eligible_app_ids"]
            for assignments in assignments_by_user.values()
        ]
    )

    common_rows = build_common_rows(
        common_group_ids,
        common_app_ids,
        group_catalog,
        app_catalog,
    )

    return detail_rows, common_rows, common_group_ids, common_app_ids


def build_common_rows(
    common_group_ids,
    common_app_ids,
    group_catalog,
    app_catalog,
):
    common_rows = []

    for group_id in common_group_ids:
        group = group_catalog[group_id]
        group_profile = group.get("profile") or {}

        common_rows.append(
            {
                "assignment_type": "GROUP",
                "assignment_name": group_profile.get("name", ""),
                "assignment_id": group_id,
                "assignment_status": "",
                "application_internal_name": "",
                "group_type": group.get("type", ""),
                "group_description": group_profile.get("description", ""),
            }
        )

    for app_id in common_app_ids:
        app = app_catalog[app_id]

        common_rows.append(
            {
                "assignment_type": "APPLICATION",
                "assignment_name": app.get("label", ""),
                "assignment_id": app_id,
                "assignment_status": app.get("status", ""),
                "application_internal_name": app.get("name", ""),
                "group_type": "",
                "group_description": "",
            }
        )

    return common_rows


# ----------------------------------------------------------------------
# CSV output
# ----------------------------------------------------------------------


def write_detail_report(rows):
    fieldnames = [
        "input_login",
        "user_login",
        "user_id",
        "user_status",
        "user_last_login",
        "assignment_type",
        "assignment_name",
        "assignment_id",
        "assignment_status",
        "assignment_scope",
        "application_internal_name",
        "application_username",
        "group_type",
        "group_description",
        "excluded_from_common_match",
    ]

    rows.sort(
        key=lambda row: (
            row["input_login"].casefold(),
            row["assignment_type"],
            row["assignment_name"].casefold(),
            row["assignment_id"],
        )
    )

    with open(
        DETAIL_OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_common_report(rows):
    fieldnames = [
        "assignment_type",
        "assignment_name",
        "assignment_id",
        "assignment_status",
        "application_internal_name",
        "group_type",
        "group_description",
    ]

    rows.sort(
        key=lambda row: (
            row["assignment_type"],
            row["assignment_name"].casefold(),
            row["assignment_id"],
        )
    )

    with open(
        COMMON_OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def filename_user_component(login):
    """
    Convert an Okta login into a safe, readable filename component.

    For email-style logins, use the portion before @. Other logins are
    used in full. Unsafe filename characters are replaced with underscores.
    """

    login = str(login or "").strip()
    username = login.split("@", 1)[0] if "@" in login else login
    username = re.sub(r"[^A-Za-z0-9._-]+", "_", username)
    return username.strip("._-") or "unknown_user"


def write_common_groups_and_apps_text_report(rows, user_logins):
    """
    Write common groups and applications in two separate text blocks.

    The filename includes every resolved username and the local run date.
    """

    generated_at = datetime.now().astimezone()
    report_date = generated_at.strftime("%Y-%m-%d")
    report_timestamp = generated_at.strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )

    filename_users = "".join(
        f"_({filename_user_component(login)})"
        for login in user_logins
    )

    output_filename = (
        f"okta_common_groups_and_apps"
        f"{filename_users}"
        f"_({report_date}).txt"
    )

    display_users = ", ".join(
        str(login)
        for login in user_logins
    )

    group_names = sorted(
        {
            str(row.get("assignment_name") or "")
            for row in rows
            if (
                row.get("assignment_type") == "GROUP"
                and str(row.get("assignment_name") or "")
            )
        },
        key=str.casefold,
    )

    application_names = sorted(
        {
            str(row.get("assignment_name") or "")
            for row in rows
            if (
                row.get("assignment_type") == "APPLICATION"
                and str(row.get("assignment_name") or "")
            )
        },
        key=str.casefold,
    )

    with open(
        output_filename,
        "w",
        encoding="utf-8",
    ) as output_file:
        output_file.write(
            f"Okta groups common to {display_users} - "
            f"{report_timestamp}\n"
        )

        if group_names:
            for group_name in group_names:
                output_file.write(f"{group_name}\n")
        else:
            output_file.write("(none)\n")

        output_file.write("\n")

        output_file.write(
            f"Okta applications common to {display_users} - "
            f"{report_timestamp}\n"
        )

        if application_names:
            for application_name in application_names:
                output_file.write(f"{application_name}\n")
        else:
            output_file.write("(none)\n")

    return output_filename


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------


def main():
    logger.info("Starting Okta common-assignment report.")

    input_logins = normalize_input_logins(USER_LOGINS)
    logger.info("Input users: %s", len(input_logins))
    logger.info("Configured ignored group names: %s", len(IGNORED_GROUPS))
    logger.info(
        "Configured ignored application names: %s",
        len(IGNORE_APPLICATIONS),
    )

    resolved_users = []
    unresolved_logins = []

    for login in input_logins:
        user = resolve_user_by_login(login)

        if user is None:
            unresolved_logins.append(login)
            continue

        resolved_users.append(
            {
                "input_login": login,
                "user": user,
            }
        )

    if unresolved_logins:
        logger.error(
            "Unresolved user logins: %s",
            ", ".join(unresolved_logins),
        )

        if FAIL_ON_UNRESOLVED_USER:
            raise RuntimeError(
                "One or more user logins could not be resolved. "
                "No common-assignment report was created."
            )

    if not resolved_users:
        raise RuntimeError("No Okta users were resolved.")

    if len(resolved_users) != len(input_logins):
        logger.warning(
            "Common assignments will be calculated across %s resolved users "
            "instead of all %s input logins.",
            len(resolved_users),
            len(input_logins),
        )

    detail_rows, common_rows, common_group_ids, common_app_ids = collect_reports(
        resolved_users
    )

    write_detail_report(detail_rows)
    write_common_report(common_rows)

    resolved_logins = [
        str(
            user_record["user"]
            .get("profile", {})
            .get("login")
            or user_record["input_login"]
        )
        for user_record in resolved_users
    ]

    common_text_output_file = (
        write_common_groups_and_apps_text_report(
            common_rows,
            resolved_logins,
        )
    )

    logger.info("Common groups after exclusions: %s", len(common_group_ids))
    logger.info("Common applications: %s", len(common_app_ids))

    if common_rows:
        logger.info("Assignments common to every resolved user:")
        for row in sorted(
            common_rows,
            key=lambda item: (
                item["assignment_type"],
                item["assignment_name"].casefold(),
            ),
        ):
            logger.info(
                "COMMON %s: %s (%s)",
                row["assignment_type"],
                row["assignment_name"],
                row["assignment_id"],
            )
    else:
        logger.info(
            "No non-ignored assignments are common to every resolved user."
        )

    logger.info("Detail rows: %s", len(detail_rows))
    logger.info("Common rows: %s", len(common_rows))
    logger.info("Detail report: %s", DETAIL_OUTPUT_FILE)
    logger.info("Common report: %s", COMMON_OUTPUT_FILE)
    logger.info(
        "Common groups and applications text report: %s",
        common_text_output_file,
    )
    logger.info("Log file: %s", LOG_FILE)
    logger.info("Report complete.")


if __name__ == "__main__":
    main()
