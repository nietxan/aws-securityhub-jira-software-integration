import logging
import sys
import os
import boto3
from jira import JIRA
import utils
from typing import Dict, Any, Optional
import json
from botocore.exceptions import ClientError, BotoCoreError

sys.path.append('lib')

logger = logging.getLogger('')
logger.setLevel(logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler())

securityhub = boto3.client('securityhub')
secretsmanager = boto3.client('secretsmanager')

# Constants for workflow states
WORKFLOW_NEW = "NEW"
WORKFLOW_NOTIFIED = "NOTIFIED"
WORKFLOW_RESOLVED = "RESOLVED"
WORKFLOW_SUPPRESSED = "SUPPRESSED"

# Constants for record states
RECORD_ACTIVE = "ACTIVE"
RECORD_ARCHIVED = "ARCHIVED"


def get_security_hub_finding(finding_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a finding from Security Hub by ID.

    Args:
        finding_id: The unique finding identifier

    Returns:
        Finding data if found, None otherwise
    """
    try:
        results = securityhub.get_findings(
            Filters={
                "Id": [{
                    'Value': finding_id,
                    'Comparison': 'EQUALS'
                }]
            }
        )

        if len(results["Findings"]) > 0:
            return results["Findings"][0]
        else:
            logger.warning(f"No Security Hub finding found for ID: {finding_id}")
            return None

    except ClientError as e:
        logger.error(f"AWS client error retrieving finding {finding_id}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error retrieving finding {finding_id}: {str(e)}")
        return None


def sync_jira_to_security_hub(
    jira_client: JIRA, 
    ticket: str, 
    finding_id: str, 
    finding: Dict[str, Any]
) -> bool:
    """
    Synchronize JIRA ticket status to Security Hub finding.
    
    Args:
        jira_client: JIRA client instance
        ticket: JIRA ticket key
        finding_id: Security Hub finding ID
        finding: Security Hub finding data
        
    Returns:
        True if sync was successful, False otherwise
    """
    try:
        finding_status = finding["Workflow"]["Status"]
        product_arn = finding["ProductArn"]
        record_state = finding["RecordState"]
        
        # Check JIRA ticket status and sync accordingly
        if utils.is_suppressed(jira_client, ticket) and finding_status != WORKFLOW_SUPPRESSED:
            # If accepted or false positive in JIRA, mark as suppressed in Security Hub
            logger.info(f"Suppressing {finding_id} based on {ticket}")
            utils.update_securityhub(
                securityhub, finding_id, product_arn, WORKFLOW_SUPPRESSED, 
                f'JIRA Ticket: {ticket}'
            )
            return True
        
        elif utils.is_closed(jira_client, ticket) and finding_status != WORKFLOW_RESOLVED:
            # If closed in JIRA, mark as Resolved in Security Hub
            logger.info(f"Marking as resolved {finding_id} based on {ticket}")
            utils.update_securityhub(
                securityhub, finding_id, product_arn, WORKFLOW_RESOLVED, 
                'JIRA Ticket was resolved'
            )
            return True
        
        elif not utils.is_closed(jira_client, ticket) and not utils.is_suppressed(jira_client, ticket):
            if record_state != RECORD_ARCHIVED and finding_status != WORKFLOW_NOTIFIED:
                # If Security Hub finding is still ACTIVE but not NOTIFIED and JIRA is not closed, 
                # move back to NOTIFIED
                logger.info(f"Reopening {finding_id} based on {ticket}")
                utils.update_securityhub(
                    securityhub, finding_id, product_arn, WORKFLOW_NOTIFIED, 
                    f'JIRA Ticket: {ticket}'
                )
                return True

            elif record_state == RECORD_ARCHIVED and finding_status != WORKFLOW_RESOLVED:
                # If Security Hub finding is ARCHIVED, then it was resolved, 
                # close JIRA issue and resolve Security Hub
                logger.info(f"Closing {ticket} based on {finding_id} archived status")
                utils.close_jira_issue(jira_client, ticket)
                utils.update_securityhub(
                    securityhub, finding_id, product_arn, WORKFLOW_RESOLVED, 
                    f'Closed JIRA Ticket {ticket}'
                )
                return True

        return False

    except Exception as e:
        logger.error(f"Error syncing ticket {ticket} with finding {finding_id}: {str(e)}")
        return False


def process_jira_ticket(
    jira_client: JIRA, 
    ticket: str, 
    project_key: str, 
    issuetype_name: str
) -> bool:
    """
    Process a single JIRA ticket for synchronization.

    Args:
        jira_client: JIRA client instance
        ticket: JIRA ticket object or key
        project_key: JIRA project key
        issuetype_name: JIRA issue type name

    Returns:
        True if processing was successful, False otherwise
    """
    try:
        logger.info(f"Checking {ticket}")

        finding_id = utils.get_finding_id_from(ticket)
        if not finding_id:
            logger.warning(f"Could not extract finding ID from ticket {ticket}")
            return False

        finding = get_security_hub_finding(finding_id)
        if not finding:
            raise UserWarning(
                f"aws-sec label found for {ticket} but couldn't find the related Security Hub finding"
            )

        return sync_jira_to_security_hub(jira_client, ticket, finding_id, finding)

    except UserWarning as e:
        logger.error(str(e))
        return False
    except Exception as e:
        logger.error(f"Unexpected error processing ticket {ticket}: {str(e)}")
        return False


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler function for syncing JIRA tickets with Security Hub.

    Args:
        event: Lambda event data
        context: Lambda context

    Returns:
        Response dictionary with processing results
    """
    logger.info(f"Starting Security Hub sync process")

    try:
        # Validate required environment variables
        utils.validate_environments(["JIRA_API_TOKEN", "AWS_REGION"])

        # Extract environment variables
        region = os.environ['AWS_REGION']
        jira_instance = os.environ['JIRA_INSTANCE']
        jira_credentials = os.environ.get("JIRA_API_TOKEN")
        project_key = os.environ['JIRA_PROJECT_KEY']
        issuetype_name = os.environ['JIRA_ISSUETYPE']

        # Initialize JIRA client
        jira_client = utils.get_jira_client(secretsmanager, jira_instance, jira_credentials)

        # Get latest updated findings from JIRA
        logger.info(f"Fetching latest updated JIRA tickets for project {project_key}")
        latest_tickets = utils.get_jira_latest_updated_findings(
                jira_client, project_key, issuetype_name
                )

        logger.info(f"Found {len(latest_tickets)} tickets to process")

        processed_count = 0
        success_count = 0
        error_count = 0

        for ticket in latest_tickets:
            processed_count += 1

            if process_jira_ticket(jira_client, ticket, project_key, issuetype_name):
                success_count += 1
            else:
                error_count += 1

        logger.info(
            f"Sync complete. Processed: {processed_count}, "
            f"Successful: {success_count}, Errors: {error_count}"
        )

        return {
            "statusCode": 200,
            "body": json.dumps({
                "processed": processed_count,
                "successful": success_count,
                "errors": error_count,
                "region": region,
                "project_key": project_key
            })
        }

    except Exception as e:
        logger.error(f"Fatal error in sync process: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e),
                "message": "Sync process failed"
            })
        }


if __name__ == "__main__":
    """Local testing entry point."""
    try:
        result = lambda_handler({}, None)
        print(f"Local execution result: {result}")

        # Exit with appropriate code based on result
        if result.get("statusCode") == 200:
            sys.exit(0)
        else:
            sys.exit(1)

    except Exception as e:
        logger.error(f"Error in local execution: {str(e)}")
        sys.exit(1)
