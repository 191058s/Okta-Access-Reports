import csv
import logging
import time
from urllib.parse import quote

import requests


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

OKTA_DOMAIN = "https://YOURDOMAIN.okta.com"
OKTA_API_TOKEN = "ADD_KEY"


MATCH_PATTERNS = [
    "AWS",
    "Web services",
    "Amazon",
]

# Match both the visible application label and Okta's internal app name.
MATCH_INTERNAL_APP_NAME = True

# False includes suspended users, inactive assignments, and inactive apps.
ONLY_ACTIVE_ACCESS = False

APP_OUTPUT_FILE = "okta_matching_app_access.csv"
GROUP_OUTPUT_FILE = "okta_matching_group_members.csv"
LOG_FILE = "okta_access_report.log"

REQUEST_TIMEOUT_SECONDS = 60
MAX_RETRIES = 5


# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------

logger = logging.getLogger("okta_access_report")
logger.setLevel(logging.INFO)
logger.propagate = False

log_formatter = logging.Formatter(
    "%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

file_handler = logging.FileHandler(
    LOG_FILE,
    encoding="utf-8",
)
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
        "User-Agent": "Infosec-Okta-Access-Report-RO/1.0",
    }
)

# Prevent duplicate user API requests when the same user appears in
# several applications or groups.
user_cache = {}


def okta_get(url, params=None):
    """
    Perform an Okta GET request with rate-limit and transient-error
    retries.
    """

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
                "Request error for %s: %s. "
                "Retrying in %s seconds.",
                url,
                exc,
                sleep_seconds,
            )

            time.sleep(sleep_seconds)
            continue

        if response.status_code == 429:
            if attempt == MAX_RETRIES:
                logger.error(
                    "Okta rate limit remained active after "
                    "%s attempts: %s",
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

            sleep_seconds = max(
                reset_time - int(time.time()),
                1,
            ) + 1

            logger.warning(
                "Okta rate limit reached. Waiting %s seconds "
                "before retrying %s.",
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
                "Okta returned HTTP %s for %s. "
                "Retrying in %s seconds.",
                response.status_code,
                response.url,
                sleep_seconds,
            )

            time.sleep(sleep_seconds)
            continue

        try:
            response.raise_for_status()

        except requests.HTTPError:
            logger.error(
                "Request failed: %s",
                response.url,
            )
            logger.error(
                "Response: %s",
                response.text,
            )
            raise

        return response

    raise RuntimeError(
        f"Request failed after retries: {url}"
    )


def get_all_pages(url, params=None):
    """
    Yield every object from an Okta cursor-paginated collection
    endpoint.
    """

    while url:
        response = okta_get(
            url,
            params=params,
        )

        data = response.json()

        if not isinstance(data, list):
            raise RuntimeError(
                f"Expected a list from {response.url}"
            )

        yield from data

        url = response.links.get(
            "next",
            {},
        ).get("url")

        # Okta's next URL already includes the required query
        # parameters.
        params = None


# ----------------------------------------------------------------------
# Matching and user helpers
# ----------------------------------------------------------------------

def matching_patterns(*values):
    """
    Return the configured patterns found in any supplied value.
    """

    normalized_values = [
        str(value or "").casefold()
        for value in values
    ]

    return [
        pattern
        for pattern in MATCH_PATTERNS
        if any(
            pattern.casefold() in value
            for value in normalized_values
        )
    ]


def application_matches(app):
    app_label = app.get("label", "")

    if MATCH_INTERNAL_APP_NAME:
        app_internal_name = app.get("name", "")
    else:
        app_internal_name = ""

    return bool(
        matching_patterns(
            app_label,
            app_internal_name,
        )
    )


def group_matches(group):
    group_name = (
        group.get("profile", {}).get("name", "")
    )

    return bool(
        matching_patterns(group_name)
    )


def get_full_user(user_id, candidate_user=None):
    """
    Return a user object containing lastLogin.

    Application expansion and group membership normally return a
    user object. A direct user lookup is used only when the supplied
    object doesn't contain lastLogin.
    """

    if user_id in user_cache:
        return user_cache[user_id]

    if (
        candidate_user
        and isinstance(candidate_user, dict)
        and candidate_user.get("profile") is not None
        and "lastLogin" in candidate_user
    ):
        user_cache[user_id] = candidate_user
        return candidate_user

    logger.info(
        "Retrieving full Okta user record for %s.",
        user_id,
    )

    encoded_user_id = quote(
        user_id,
        safe="",
    )

    response = okta_get(
        f"{OKTA_DOMAIN}/api/v1/users/{encoded_user_id}"
    )

    user = response.json()
    user_cache[user_id] = user

    return user


def user_report_fields(user):
    """
    Return the common user columns used by both reports.
    """

    profile = user.get("profile", {})

    return {
        "user_login": profile.get("login", ""),
        "first_name": profile.get("firstName", ""),
        "last_name": profile.get("lastName", ""),
        "email": profile.get("email", ""),
        "user_id": user.get("id", ""),
        "user_status": user.get("status", ""),
        "user_last_login": (
            user.get("lastLogin") or ""
        ),
    }


# ----------------------------------------------------------------------
# Application access report
# ----------------------------------------------------------------------

def collect_application_report():
    logger.info("Retrieving applications.")

    applications = list(
        get_all_pages(
            f"{OKTA_DOMAIN}/api/v1/apps",
            params={
                "limit": 200,
            },
        )
    )

    matching_apps = [
        app
        for app in applications
        if application_matches(app)
    ]

    matching_apps.sort(
        key=lambda app: str(
            app.get("label") or ""
        ).casefold()
    )

    logger.info(
        "Applications retrieved: %s",
        len(applications),
    )

    logger.info(
        "Applications matching any of %s: %s",
        MATCH_PATTERNS,
        len(matching_apps),
    )

    rows = []

    for app_number, app in enumerate(
        matching_apps,
        start=1,
    ):
        app_id = app.get("id", "")
        app_label = app.get("label", "")
        app_name = app.get("name", "")
        app_status = app.get("status", "")

        if MATCH_INTERNAL_APP_NAME:
            internal_name_for_matching = app_name
        else:
            internal_name_for_matching = ""

        app_matches = matching_patterns(
            app_label,
            internal_name_for_matching,
        )

        logger.info(
            "[%s/%s] Retrieving users for application: %s",
            app_number,
            len(matching_apps),
            app_label,
        )

        encoded_app_id = quote(
            app_id,
            safe="",
        )

        app_users_url = (
            f"{OKTA_DOMAIN}/api/v1/apps/"
            f"{encoded_app_id}/users"
        )

        app_user_count = 0
        included_count = 0

        for app_user in get_all_pages(
            app_users_url,
            params={
                "limit": 500,
                "expand": "user",
            },
        ):
            app_user_count += 1

            user_id = app_user.get("id", "")

            candidate_user = (
                app_user
                .get("_embedded", {})
                .get("user")
            )

            user = get_full_user(
                user_id,
                candidate_user,
            )

            user_status = user.get("status", "")
            app_user_status = app_user.get(
                "status",
                "",
            )

            all_statuses_active = (
                app_status == "ACTIVE"
                and user_status == "ACTIVE"
                and app_user_status == "ACTIVE"
            )

            if (
                ONLY_ACTIVE_ACCESS
                and not all_statuses_active
            ):
                continue

            app_profile = app_user.get(
                "profile",
                {},
            )

            app_credentials = app_user.get(
                "credentials",
                {},
            )

            application_username = (
                app_credentials.get("userName")
                or app_profile.get("userName")
                or ""
            )

            row = {
                "application_label": app_label,
                "application_internal_name": app_name,
                "application_id": app_id,
                "application_status": app_status,
                "matched_patterns": "; ".join(
                    app_matches
                ),
                **user_report_fields(user),
                "assignment_scope": app_user.get(
                    "scope",
                    "",
                ),
                "application_username": (
                    application_username
                ),
                "application_user_status": (
                    app_user_status
                ),
                "assignment_created": app_user.get(
                    "created",
                    "",
                ),
                "assignment_last_updated": (
                    app_user.get(
                        "lastUpdated",
                        "",
                    )
                ),
                "all_statuses_active": (
                    "YES"
                    if all_statuses_active
                    else "NO"
                ),
            }

            rows.append(row)
            included_count += 1

        logger.info(
            "Application users retrieved for %s: %s; "
            "included in report: %s",
            app_label,
            app_user_count,
            included_count,
        )

    return rows, matching_apps


def write_application_report(rows):
    fieldnames = [
        "application_label",
        "application_internal_name",
        "application_id",
        "application_status",
        "matched_patterns",
        "user_login",
        "first_name",
        "last_name",
        "email",
        "user_id",
        "user_status",
        "user_last_login",
        "assignment_scope",
        "application_username",
        "application_user_status",
        "assignment_created",
        "assignment_last_updated",
        "all_statuses_active",
    ]

    rows.sort(
        key=lambda row: (
            row["application_label"].casefold(),
            row["user_login"].casefold(),
        )
    )

    with open(
        APP_OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


# ----------------------------------------------------------------------
# Group membership report
# ----------------------------------------------------------------------

def collect_group_report():
    logger.info("Retrieving groups.")

    groups = list(
        get_all_pages(
            f"{OKTA_DOMAIN}/api/v1/groups",
            params={
                "limit": 200,
            },
        )
    )

    matching_groups = [
        group
        for group in groups
        if group_matches(group)
    ]

    matching_groups.sort(
        key=lambda group: str(
            group
            .get("profile", {})
            .get("name")
            or ""
        ).casefold()
    )

    logger.info(
        "Groups retrieved: %s",
        len(groups),
    )

    logger.info(
        "Groups matching any of %s: %s",
        MATCH_PATTERNS,
        len(matching_groups),
    )

    rows = []

    for group_number, group in enumerate(
        matching_groups,
        start=1,
    ):
        group_id = group.get("id", "")
        group_type = group.get("type", "")
        group_profile = group.get("profile", {})

        group_name = group_profile.get(
            "name",
            "",
        )

        group_description = group_profile.get(
            "description",
            "",
        )

        group_matches_found = matching_patterns(
            group_name
        )

        logger.info(
            "[%s/%s] Retrieving members for group: %s",
            group_number,
            len(matching_groups),
            group_name,
        )

        encoded_group_id = quote(
            group_id,
            safe="",
        )

        group_users_url = (
            f"{OKTA_DOMAIN}/api/v1/groups/"
            f"{encoded_group_id}/users"
        )

        member_count = 0
        included_count = 0

        for candidate_user in get_all_pages(
            group_users_url,
            params={
                "limit": 200,
            },
        ):
            member_count += 1

            user_id = candidate_user.get(
                "id",
                "",
            )

            user = get_full_user(
                user_id,
                candidate_user,
            )

            if (
                ONLY_ACTIVE_ACCESS
                and user.get("status") != "ACTIVE"
            ):
                continue

            row = {
                "group_name": group_name,
                "group_description": (
                    group_description
                ),
                "group_id": group_id,
                "group_type": group_type,
                "matched_patterns": "; ".join(
                    group_matches_found
                ),
                **user_report_fields(user),
            }

            rows.append(row)
            included_count += 1

        logger.info(
            "Group members retrieved for %s: %s; "
            "included in report: %s",
            group_name,
            member_count,
            included_count,
        )

    return rows, matching_groups


def write_group_report(rows):
    fieldnames = [
        "group_name",
        "group_description",
        "group_id",
        "group_type",
        "matched_patterns",
        "user_login",
        "first_name",
        "last_name",
        "email",
        "user_id",
        "user_status",
        "user_last_login",
    ]

    rows.sort(
        key=lambda row: (
            row["group_name"].casefold(),
            row["user_login"].casefold(),
        )
    )

    with open(
        GROUP_OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    logger.info(
        "Starting Okta access report."
    )

    logger.info(
        "Match patterns: %s",
        MATCH_PATTERNS,
    )

    logger.info(
        "Only active access: %s",
        ONLY_ACTIVE_ACCESS,
    )

    application_rows, matching_apps = (
        collect_application_report()
    )

    write_application_report(
        application_rows
    )

    group_rows, matching_groups = (
        collect_group_report()
    )

    write_group_report(
        group_rows
    )

    unique_application_users = {
        row["user_id"]
        for row in application_rows
        if row["user_id"]
    }

    unique_group_users = {
        row["user_id"]
        for row in group_rows
        if row["user_id"]
    }

    direct_assignments = sum(
        1
        for row in application_rows
        if row["assignment_scope"] == "USER"
    )

    group_derived_assignments = sum(
        1
        for row in application_rows
        if row["assignment_scope"] == "GROUP"
    )

    logger.info("Report complete.")

    logger.info(
        "Matching applications: %s",
        len(matching_apps),
    )

    logger.info(
        "Application/user rows: %s",
        len(application_rows),
    )

    logger.info(
        "Unique application users: %s",
        len(unique_application_users),
    )

    logger.info(
        "Direct application assignments: %s",
        direct_assignments,
    )

    logger.info(
        "Group-derived application assignments: %s",
        group_derived_assignments,
    )

    logger.info(
        "Matching groups: %s",
        len(matching_groups),
    )

    logger.info(
        "Group/member rows: %s",
        len(group_rows),
    )

    logger.info(
        "Unique group members: %s",
        len(unique_group_users),
    )

    logger.info(
        "Application report: %s",
        APP_OUTPUT_FILE,
    )

    logger.info(
        "Group report: %s",
        GROUP_OUTPUT_FILE,
    )

    logger.info(
        "Log file: %s",
        LOG_FILE,
    )


if __name__ == "__main__":
    main()
