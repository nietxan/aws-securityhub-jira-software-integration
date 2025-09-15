import logging
import sys
import os
import boto3
from typing import Optional, List, Any, Dict
from jira import JIRA
import utils

sys.path.append('lib')

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler())

securityhub = boto3.client('securityhub')
secretsmanager = boto3.client('secretsmanager')


def sync_finding_with_jira(jira_client: JIRA, ticket: Any, project_key: str, 
                           issuetype_name: str) -> None:
    """
    Sync a single JIRA ticket with its corresponding Security Hub finding.
    Updated to work with parent/subtask structure and simplified status handling.

    Args:
        jira_client: JIRA client instance
        ticket: JIRA ticket object
        project_key: JIRA project key
        issuetype_name: JIRA issue type name
    """
    try:
        logger.info(f"Checking {ticket}")
        
        # Check if this is a subtask or parent issue
        is_subtask = hasattr(ticket.fields, 'parent') and ticket.fields.parent is not None
        
        if is_subtask:
            # For subtasks, get finding ID from description or labels
            finding_id = utils.get_finding_id_from_subtask(ticket)
            if not finding_id:
                logger.warning(f"Could not extract finding ID from subtask {ticket}")
                return
        else:
            # For parent issues, skip individual finding sync
            logger.info(f"Skipping parent issue {ticket} - no individual finding to sync")
            return

        # Get the finding from Security Hub
        results = securityhub.get_findings(Filters={"Id": [{
            'Value': finding_id,
            'Comparison': 'EQUALS'
            }]})

        if not results.get("Findings"):
            logger.warning(f"Could not find Security Hub finding for {finding_id}")
            return

        finding = results["Findings"][0]
        finding_status = finding["Workflow"]["Status"]
        product_arn = finding["ProductArn"]
        record_state = finding["RecordState"]

        # Simplified status handling - just sync basic states
        if record_state == "ARCHIVED" and finding_status != "RESOLVED":
            logger.info(f"Marking as resolved {finding_id} based on {ticket}")
            utils.update_securityhub(
                securityhub, finding_id, product_arn, "RESOLVED", f'JIRA Ticket {ticket} was resolved')
        elif record_state == "ACTIVE" and finding_status != "NOTIFIED":
            logger.info(f"Reopen {finding_id} based on {ticket}")
            utils.update_securityhub(
                securityhub, finding_id, product_arn, "NOTIFIED", f'JIRA Ticket: {ticket}')

    except UserWarning as e:
        logger.error(f"User warning for ticket {ticket}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error processing ticket {ticket}: {e}", exc_info=True)


def lambda_handler(event: Optional[Any], context: Optional[Any]) -> None:
    """
    Main Lambda handler function for syncing Security Hub findings with JIRA.

    Args:
        event: EventBridge event (not used in this function)
        context: Lambda context object (not used in this function)
    """
    try:
        utils.validate_environments(["JIRA_API_TOKEN", "AWS_REGION"])

        # Extract environment variables
        region = os.environ['AWS_REGION']
        jira_instance = os.environ['JIRA_INSTANCE']
        jira_credentials = os.environ.get("JIRA_API_TOKEN")
        project_key = os.environ['JIRA_PROJECT_KEY']
        issuetype_name = os.environ['JIRA_ISSUETYPE']

        # Get JIRA client
        jira_client = utils.get_jira_client(secretsmanager, jira_instance, jira_credentials)

        # Get latest updated findings from JIRA (both parent issues and subtasks)
        latest_tickets = utils.get_jira_latest_updated_findings(
                jira_client, project_key, issuetype_name)
        
        # Also get subtasks
        latest_subtasks = jira_client.search_issues(
            'Project = {0} AND issuetype = "Subtask" AND updated >= -2w'.format(project_key), 
            maxResults=False)

        all_tickets = latest_tickets + latest_subtasks

        if not all_tickets:
            logger.info("No recent JIRA tickets found to sync")
            return

        logger.info(f"Syncing {len(all_tickets)} JIRA tickets (parent issues and subtasks) with Security Hub")

        # Process each ticket
        for ticket in all_tickets:
            sync_finding_with_jira(jira_client, ticket, project_key, issuetype_name)

    except Exception as e:
        logger.error(f"Fatal error in lambda_handler: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    lambda_handler(None, None)
