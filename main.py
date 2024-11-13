from pypanther import LogType, get_panther_rules, register
from pypanther.rules.github import GitHubActionFailed

# Get all built-in GitHub Audit rules
git_rules = get_panther_rules(log_types=[LogType.GITHUB_AUDIT])

# Override the default rule values to enable and increase the deduplication window
GitHubActionFailed.override(
    enabled=True,
    dedup_period_minutes=60 * 8,
)

# Add a tag along the default tags
GitHubActionFailed.extend(
    tags=["CorpSec", "test"],
)

# Set a required configuration on the rule for higher accuracy
GitHubActionFailed.MONITORED_ACTIONS = {
    "main_app": ["code_scanning"],
}


# Write a new filter function to check for bot activity
def github_is_bot_filter(event):
    return bool(event.get("actor_is_bot"))


# Register and enable rules to be uploaded and tested
register(git_rules)
