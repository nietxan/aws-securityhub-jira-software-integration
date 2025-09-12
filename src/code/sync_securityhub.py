import logging
import sys
import os
import boto3
from typing import Optional, List, Any
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

    Args:
        jira_client: JIRA client instance
        ticket: JIRA ticket object
        project_key: JIRA project key
        issuetype_name: JIRA issue type name
    """
    try:
        logger.info(f"Checking {ticket}")
        finding_id = utils.get_finding_id_from(ticket)

        if not finding_id:
            logger.warning(f"Could not extract finding ID from ticket {ticket}")
            return

        # Get the finding from Security Hub
        results = securityhub.get_findings(Filters={"Id": [{
            'Value': finding_id,
            'Comparison': 'EQUALS'
            }]})

        if not results.get("Findings"):
            raise UserWarning(f"aws-sec label found for {ticket} but couldn't find the related Security Hub finding")

        finding = results["Findings"][0]
        finding_status = finding["Workflow"]["Status"]
        product_arn = finding["ProductArn"]
        record_state = finding["RecordState"]

        # Handle suppressed findings
        if utils.is_suppressed(jira_client, ticket) and finding_status != "SUPPRESSED":
            logger.info(f"Suppress {finding_id} based on {ticket}")
            utils.update_securityhub(
                    securityhub, finding_id, product_arn, "SUPPRESSED", f'JIRA Ticket: {ticket}')

        # Handle closed findings
    elif utils.is_closed(jira_client, ticket) and finding_status != "RESOLVED":
        logger.info(f"Marking as resolved {finding_id} based on {ticket}")
            utils.update_securityhub(
                    securityhub, finding_id, product_arn, "RESOLVED", 'JIRA Ticket was resolved')

        # Handle active findings that are not closed or suppressed
    elif not utils.is_closed(jira_client, ticket) and not utils.is_suppressed(jira_client, ticket):
        if record_state != "ARCHIVED" and finding_status != "NOTIFIED":
            # Reopen if Security Hub finding is still ACTIVE but not NOTIFIED
                logger.info(f"Reopen {finding_id} based on {ticket}")
                utils.update_securityhub(
                        securityhub, finding_id, product_arn, "NOTIFIED", f'JIRA Ticket: {ticket}')

            elif record_state == "ARCHIVED" and finding_status != "RESOLVED":
                # Close JIRA issue if Security Hub finding is ARCHIVED
                logger.info(f"Closing {ticket} based on {finding_id} archived status")
                utils.close_jira_issue(jira_client, ticket)
                utils.update_securityhub(
                        securityhub, finding_id, product_arn, "RESOLVED", f'Closed JIRA Ticket {ticket}')

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

        # Get latest updated findings from JIRA
        latest_tickets = utils.get_jira_latest_updated_findings(
                jira_client, project_key, issuetype_name)

        if not latest_tickets:
            logger.info("No recent JIRA tickets found to sync")
            return

        logger.info(f"Syncing {len(latest_tickets)} JIRA tickets with Security Hub")

        # Process each ticket
        for ticket in latest_tickets:
            sync_finding_with_jira(jira_client, ticket, project_key, issuetype_name)

    except Exception as e:
        logger.error(f"Fatal error in lambda_handler: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    lambda_handler(None, None)
