import logging
import json
import os
import boto3
import sys
from jira import JIRA
import utils
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

# Set global logger
logger = logging.getLogger('')
logger.setLevel(logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler())

securityhub = boto3.client('securityhub')
secretsmanager = boto3.client('secretsmanager')

# Constants for event types
EVENT_TYPE_CUSTOM_ACTION = "Security Hub Findings - Custom Action"
EVENT_TYPE_IMPORTED = "Security Hub Findings - Imported"
EVENT_TYPE_IMPORTED_V2 = "Findings Imported V2"

# Constants for workflow states
WORKFLOW_NEW = "NEW"
WORKFLOW_NOTIFIED = "NOTIFIED"
WORKFLOW_RESOLVED = "RESOLVED"
WORKFLOW_SUPPRESSED = "SUPPRESSED"

# Constants for record states
RECORD_ACTIVE = "ACTIVE"
RECORD_ARCHIVED = "ARCHIVED"


def normalize_finding_data(finding: Dict[str, Any], event_type: str) -> Dict[str, Any]:
    """
    Normalize finding data from different event formats to a consistent structure.

    Args:
        finding: Raw finding data from the event
        event_type: Type of the event (e.g., "Findings Imported V2")

    Returns:
        Normalized finding data with consistent field names
    """
    if event_type == EVENT_TYPE_IMPORTED_V2:
        # Handle new "Findings Imported V2" format
        normalized = {
            "AwsAccountId": finding.get("cloud", {}).get("account", {}).get("uid", ""),
            "Description": finding.get("finding_info", {}).get("desc", ""),
            "Title": finding.get("finding_info", {}).get("title", ""),
            "Id": finding.get("finding_info", {}).get("uid", ""),
            "ProductArn": finding.get("metadata", {}).get("product", {}).get("uid", ""),
            "Resources": [],
            "Severity": {"Label": finding.get("severity", "Medium")},
            "Workflow": {"Status": _map_v2_status_to_workflow(finding.get("status", "New"))},
            "RecordState": _map_v2_status_to_record_state(finding.get("status", "New")),
            "GeneratorId": finding.get("finding_info", {}).get("uid", "")
        }

        # Extract resources from V2 format
        resources = finding.get("resources", [])
        normalized["Resources"] = []
        for resource in resources:
            resource_id = resource.get("uid", "")
            if resource_id:
                normalized["Resources"].append({"Id": resource_id})

        return normalized
    else:
        # Return original finding for legacy formats
        return finding


def _map_v2_status_to_workflow(status: str) -> str:
    """Map V2 status to workflow status."""
    status_mapping = {
        "New": WORKFLOW_NEW,
        "Active": WORKFLOW_NEW,
        "Resolved": WORKFLOW_RESOLVED,
        "Suppressed": WORKFLOW_SUPPRESSED
    }
    return status_mapping.get(status, WORKFLOW_NEW)


def _map_v2_status_to_record_state(status: str) -> str:
    """Map V2 status to record state."""
    if status in ["Resolved", "Archived"]:
        return RECORD_ARCHIVED
    return RECORD_ACTIVE


def finding_parser(finding: Dict[str, Any]) -> Tuple[str, str, str, str, str, str, List[str], str, str]:
    """
    Parse finding data and extract relevant information.

    Args:
        finding: Normalized finding data

    Returns:
        Tuple of parsed finding data
    """
    account = finding.get("AwsAccountId", "")
    description = finding.get("Description", "")
    severity = finding.get("Severity", {}).get("Label", "Medium")
    title = finding.get("Title", "")
    finding_id = finding.get("Id", "")
    product_arn = finding.get("ProductArn", "")
    resources = [resource.get('Id', '') for resource in finding.get("Resources", [])]
    status = finding.get("Workflow", {}).get("Status", WORKFLOW_NEW)
    recordstate = finding.get("RecordState", RECORD_ACTIVE)

    return account, description, severity, title, finding_id, product_arn, resources, status, recordstate


def create_jira_ticket(
    jira_client: JIRA,
    project_key: str,
    issuetype_name: str,
    product_arn: str,
    account: str,
    region: str,
    description: str,
    resources: List[str],
    severity: str,
    title: str,
    finding_id: str
) -> None:
    """
    Create a JIRA ticket for a Security Hub finding.

    Args:
        jira_client: JIRA client instance
        project_key: JIRA project key
        issuetype_name: JIRA issue type name
        product_arn: Product ARN from the finding
        account: AWS account ID
        region: AWS region
        description: Finding description
        resources: List of affected resources
        severity: Finding severity
        title: Finding title
        finding_id: Unique finding ID
    """
    try:
        resources_str = f"Resources: {resources}" if resources and "default" not in product_arn else ""

        new_issue = utils.create_ticket(
            jira_client, project_key, issuetype_name, account, region, 
            description, resources_str, severity, title, finding_id
        )

        utils.update_securityhub(
            securityhub, finding_id, product_arn, WORKFLOW_NOTIFIED, 
            f'JIRA Ticket: {new_issue}'
        )

        utils.update_jira_assignee(jira_client, new_issue, account)

        logger.info(f"Created JIRA ticket {new_issue} for finding {finding_id}")

    except Exception as e:
        logger.error(f"Failed to create JIRA ticket for finding {finding_id}: {str(e)}")
        raise


def is_automated_check(finding: Dict[str, Any]) -> bool:
    """
    Check if a finding should be automatically processed based on configuration.

    Args:
        finding: Normalized finding data

    Returns:
        True if the finding should be automatically processed
    """
    try:
        script_dir = os.path.dirname(__file__)
        config_path = os.path.join(script_dir, "config/config.json")

        with open(config_path) as config_file:
            automated_controls = json.load(config_file)

        region = os.environ['AWS_REGION']
        generator_id = finding.get("GeneratorId", "")

        if region in automated_controls.get("Controls", {}):
            return generator_id in automated_controls["Controls"][region]
        else:
            return generator_id in automated_controls.get("Controls", {}).get("default", [])

    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Error reading automation config: {str(e)}")
        return False


def process_custom_action_finding(
    finding: Dict[str, Any],
    event: Dict[str, Any],
    jira_client: JIRA,
    project_key: str,
    issuetype_name: str,
    region: str
) -> None:
    """Process findings from custom action events."""
    account, description, severity, title, finding_id, product_arn, resources, status, recordstate = finding_parser(finding)

    if event["detail"]["actionName"] != "CreateJiraIssue":
        logger.warning(f"Unknown custom action: {event['detail']['actionName']}")
        return

    if status != WORKFLOW_NEW:
        raise UserWarning(f"Finding workflow is not NEW: {finding_id}")

    if recordstate != RECORD_ACTIVE:
        raise UserWarning(f"Finding is not ACTIVE: {finding_id}")

    jira_issue = utils.get_jira_finding(jira_client, finding_id, project_key, issuetype_name)

    if not jira_issue:
        logger.info(f"Creating ticket manually for {finding_id}")
        create_jira_ticket(
            jira_client, project_key, issuetype_name, product_arn, 
            account, region, description, resources, severity, title, finding_id
        )
    else:
        logger.info(f"Finding {finding_id} already reported in ticket {jira_issue}")


def process_imported_finding(
    finding: Dict[str, Any],
    jira_client: JIRA,
    project_key: str,
    issuetype_name: str,
    region: str
) -> None:
    """Process findings from imported events."""
    account, description, severity, title, finding_id, product_arn, resources, status, recordstate = finding_parser(finding)

    if recordstate == RECORD_ARCHIVED and status == WORKFLOW_NOTIFIED:
        # Move to resolved
        jira_issue = utils.get_jira_finding(jira_client, finding_id, project_key, issuetype_name)

        if jira_issue:
            utils.close_jira_issue(jira_client, jira_issue)
            utils.update_securityhub(
                securityhub, finding_id, product_arn, WORKFLOW_RESOLVED,
                f'Closed JIRA Ticket {jira_issue}'
            )
            logger.info(f"Closed JIRA ticket {jira_issue} for archived finding {finding_id}")

    elif recordstate == RECORD_ACTIVE and status == WORKFLOW_RESOLVED:
        # Reopen if needed
        jira_issue = utils.get_jira_finding(jira_client, finding_id, project_key, issuetype_name)

        if jira_issue and utils.is_closed(jira_client, jira_issue):
            # Reopen closed ticket as it was re-detected
            utils.reopen_jira_issue(jira_client, jira_issue)
            utils.update_securityhub(
                securityhub, finding_id, product_arn, WORKFLOW_NOTIFIED,
                f'Reopening JIRA Ticket {jira_issue}'
            )
            logger.info(f"Reopened JIRA ticket {jira_issue} for re-detected finding {finding_id}")

    elif recordstate == RECORD_ACTIVE and status == WORKFLOW_NEW:
        # Check if should be automatically processed
        if is_automated_check(finding):
            jira_issue = utils.get_jira_finding(jira_client, finding_id, project_key, issuetype_name)

            if not jira_issue:
                logger.info(f"Creating ticket automatically for {finding_id}")
                create_jira_ticket(
                    jira_client, project_key, issuetype_name, product_arn,
                    account, region, description, resources, severity, title, finding_id
                )
    else:
        logger.info(f"Not performing any action for {finding_id} (status: {status}, record: {recordstate})")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler function.

    Args:
        event: Lambda event data
        context: Lambda context

    Returns:
        Response dictionary
    """
    logger.info(f"Processing event: {json.dumps(event, default=str)}")

    try:
        # Validate required environment variables
        utils.validate_environments(["JIRA_API_TOKEN", "AWS_REGION"])

        # Extract environment variables
        region = os.environ['AWS_REGION']
        project_key = os.environ['JIRA_PROJECT_KEY']
        issuetype_name = os.environ['JIRA_ISSUETYPE']
        jira_instance = os.environ['JIRA_INSTANCE']
        jira_credentials = os.environ.get("JIRA_API_TOKEN")

        # Get event type and findings
        event_type = event.get("detail-type", "")
        findings = event.get("detail", {}).get("findings", [])

        if not findings:
            logger.warning("No findings found in event")
            return {"statusCode": 200, "body": "No findings to process"}

        # Get JIRA client
        jira_client = utils.get_jira_client(secretsmanager, jira_instance, jira_credentials)

        processed_count = 0
        error_count = 0

        for finding in findings:
            try:
                # Normalize finding data based on event type
                normalized_finding = normalize_finding_data(finding, event_type)

                if event_type == EVENT_TYPE_CUSTOM_ACTION:
                    process_custom_action_finding(
                        normalized_finding, event, jira_client, 
                        project_key, issuetype_name, region
                    )
                elif event_type in [EVENT_TYPE_IMPORTED, EVENT_TYPE_IMPORTED_V2]:
                    process_imported_finding(
                        normalized_finding, jira_client, 
                        project_key, issuetype_name, region
                    )
                else:
                    logger.warning(f"Unknown event type: {event_type}")
                    continue

                processed_count += 1

            except UserWarning as e:
                logger.error(f"User warning for finding: {str(e)}")
                error_count += 1
            except Exception as e:
                logger.error(f"Error processing finding: {str(e)}")
                error_count += 1

        logger.info(f"Processing complete. Processed: {processed_count}, Errors: {error_count}")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "processed": processed_count,
                "errors": error_count,
                "event_type": event_type
            })
        }

    except Exception as e:
        logger.error(f"Fatal error in lambda_handler: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python security_hub_integration.py event.template")
        sys.exit(1)

    template = sys.argv[1]

    try:
        with open(template, "r") as event_file:
            security_hub_event = json.load(event_file)

            # Update timestamps for local testing
            local_time = datetime.now(timezone.utc).astimezone().isoformat()

            findings = security_hub_event.get("detail", {}).get("findings", [])
            for finding in findings:
                # Handle both old and new formats
                if "UpdatedAt" in finding:
                    finding["UpdatedAt"] = local_time
                elif "finding_info" in finding:
                    finding["finding_info"]["modified_time_dt"] = local_time

            result = lambda_handler(security_hub_event, None)
            print(f"Execution result: {result}")

    except FileNotFoundError:
        logger.error(f"Template file not found: {template}")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in template file: {template}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error running local test: {str(e)}")
        sys.exit(1)
