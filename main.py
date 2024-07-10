from pypanther import PantherLogType, PantherSeverity, get_panther_rules, register
from pypanther.wrap import exclude, include
from pypanther.get import table_print

from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_account_discovery import AWSCloudTrailAccountDiscovery
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_stopped import AWSCloudTrailStopped
from pypanther.rules.aws_cloudtrail_rules.aws_console_root_login import AWSConsoleRootLogin

from rules.aws_rules.alb_high_400s import AWSALBHighVol400s
from rules.custom_logs.ids_rules import HostIDSBaseRule, HostIDSMalware
from helpers.cloud import prod_account_ids, account_lookup_by_id, update_account_id_tests


########################################################
## Importing Panther-managed Rules
##
## Use get_panther_rules() to return a list of Panther-managed rules.
## Calling without arguments returns everything and passing attributes
## like LogTypes, Severity, or Tags filters rules matching the values.

# Note: Replace with your onboarded log types
onboarded_log_types = [
    PantherLogType.AWS_CloudTrail,
    PantherLogType.AWS_GuardDuty,
    PantherLogType.Okta_SystemLog,
]

# Get Panther-managed rules for onboarded log types
base_rules = get_panther_rules(LogTypes=onboarded_log_types)

## Gets all Panther-managed Rules
# all_rules = get_panther_rules()

## Get Panther-managed rules for specific severities
# high_sev_rules = get_panther_rules(
#     LogTypes=onboarded_log_types,
#     Severity=[
#         PantherSeverity.Critical,
#         PantherSeverity.High,
#     ],
# )


########################################################
## Filters and Dynamic Functions
##
## Filters include/exclude events from being evaluated by rules.
## Dynamic functions generate alert values based on event data.


def prod_account(event):
    '''
    Uses CloudTrail events to check if an account ID is in the list of production accounts.
    This uses a variable from the helpers/cloud module.
    '''
    # TODO() Change this to use event.udm('account_id')
    return event.get("recipientAccountId") in prod_account_ids


sensitive_services = {"s3", "dynamodb", "iam", "secretsmanager", "ec2"}
def guard_duty_sensitive_service(event):
    '''Uses GuardDuty findings to check if the event is for a sensitive service.'''
    service_name = event.deep_get("service", "action", "awsApiCallAction", "serviceName")
    return any(service_name.startswith(service) for service in sensitive_services)


def root_login_account(_, event):
    '''
    Generates a dynamic alert title for root logins using account mappings.
    Args:
        _ (self): The PantherRule instance (unused)
        event (dict): The CloudTrail event
    '''
    ip_address = event.get("sourceIPAddress")
    account = account_lookup_by_id(event.get("recipientAccountId"))
    return f"Root Login from [{ip_address}] in account [{account}]"


########################################################
## Overrides
##
## Apply your internal configurations to Panther-managed rules.
## This can include single attributes, multiple attributes, or filters.

# Override a single rule's severity to Low
AWSCloudTrailAccountDiscovery.Severity = PantherSeverity.Low

# Override a set of rule attributes and attach the 'prod_account' filter from above
include(prod_account)(AWSCloudTrailStopped)
# TODO(panther) This is a temproary workaround for updating AWS account IDs in rule tests
update_account_id_tests([AWSCloudTrailStopped])

# Override multiple atributes using the rule override() method
AWSCloudTrailStopped.override(
    Runbook=(
        "If the account is in production, investigate why CloudTrail was stopped. "
        "If it was intentional, ensure that the account is monitored by another CloudTrail. "
        "If it was not intentional, investigate the account for unauthorized access."
    ),
    Reports=AWSCloudTrailStopped.Reports | {"Internal": ["C.4"]},
)

# Override a title dynamic function to match internal cloud account account mappings
# Check out helpers/cloud.py for the account_lookup_by_id function
AWSConsoleRootLogin.title = root_login_account

# Add two filters to all GuardDuty rules
for rule in base_rules:
    if PantherLogType.AWS_GuardDuty in rule.LogTypes:
        # Include only production accounts
        include(guard_duty_sensitive_service)(rule)
        # Exclude any 'Discovery' tactic finding
        exclude(lambda event: event.get("type").startswith("Discovery"))(rule)


########################################################
## Register
##
## Register your rules to upload them to your Panther instance.
## Register also enables tests to be run with `pypanther test`.

## Register all rules
# register(all_rules)

# Use table_print() to pretty print the list of rules
print("Base Rules")
print(table_print(base_rules))

# Register the rules for onboarded log types
register(base_rules)

register(
    [
        AWSALBHighVol400s,
        AWSCloudTrailStopped,
        AWSCloudTrailAccountDiscovery,
        AWSConsoleRootLogin,
        HostIDSBaseRule,
        HostIDSMalware,
    ]
)