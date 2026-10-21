# Okta-Access-Reports

Two Python scripts I use for Okta access reviews. access_reports.py finds applications and groups matching names or keywords you configure, then exports their users and memberships to CSV. It includes things like account status, assignment details, and last login, with an option to limit the report to active access.

common_groups.py compares a list of Okta users and finds the groups and applications they all have in common. It also exports each user's assignments, with options to exclude certain groups or apps from the comparison. Both scripts use Okta API GET requests, handle pagination and rate limits, and write logs. Install the requests package (pip install requests), set OKTA_DOMAIN and OKTA_API_TOKEN in the scripts, update the search patterns or usernames, and run python access_reports.py or python common_groups.py. Don't commit a real API token to GitHub.

Use cases
- Review access to a specific set of applications or groups (e.g., AWS-related access in Okta).
- Find inactive users who still have app assignments or group memberships.
- Compare two or more users to see which permissions they share.
- Identify common access that may be worth reviewing for least privilege.
- Export access-review data to CSV for audits or investigations.
