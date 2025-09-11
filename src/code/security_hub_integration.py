# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import logging
import json
import os
import boto3
import sys
from typing import Dict, List, Optional, Tuple, Any
from jira import JIRA
import utils
from datetime import datetime, timezone

# set global logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler())

securityhub = boto3.client('securityhub')
secretsmanager = boto3.client('secretsmanager')


class FindingData:
    """Data class to hold finding information in a structured way."""
    
    def __init__(self, account: str, description: str, severity: str, title: str, 
                 finding_id: str, product_arn: str, resources: List[str], 
                 status: str, record_state: str, region: str = None):
        self.account = account
        self.description = description
        self.severity = severity
        self.title = title
        self.finding_id = finding_id
        self.product_arn = product_arn
        self.resources = resources
        self.status = status
        self.record_state = record_state
        self.region = region


def parse_legacy_finding(finding: Dict[str, Any]) -> FindingData:
    """Parse legacy Security Hub finding format."""
    account = finding["AwsAccountId"]
    description = finding["Description"]
    severity = finding["Severity"]["Label"]
    title = finding["Title"]
    finding_id = finding["Id"]
    product_arn = finding["ProductArn"]
    resources = [resource.get('Id') for resource in finding["Resources"]]
    status = finding["Workflow"]["Status"]
    record_state = finding["RecordState"]
    
    return FindingData(account, description, severity, title, finding_id, 
                      product_arn, resources, status, record_state)


def parse_new_finding(finding: Dict[str, Any], region: str) -> FindingData:
    """Parse new Security Hub EventBridge finding format (Findings Imported V2)."""
    # Extract account from cloud.account.uid
    account = finding.get("cloud", {}).get("account", {}).get("uid", "unknown")
    
    # Extract description from finding_info.desc
    description = finding.get("finding_info", {}).get("desc", "No description available")
    
    # Extract severity - use vendor_attributes.severity if available, otherwise severity
    severity = finding.get("vendor_attributes", {}).get("severity") or finding.get("severity", "Unknown")
    
    # Extract title from finding_info.title
    title = finding.get("finding_info", {}).get("title", "No title available")
    
    # Extract finding ID from finding_info.uid
    finding_id = finding.get("finding_info", {}).get("uid", "unknown")
    
    # Extract product ARN from metadata.product.uid
    product_arn = finding.get("metadata", {}).get("product", {}).get("uid", "unknown")
    
    # Extract resources - get UIDs from resources array
    resources = []
    for resource in finding.get("resources", []):
        if "uid" in resource:
            resources.append(resource["uid"])
    
    # Map status - new format uses different status values
    status_mapping = {
        "New": "NEW",
        "Updated": "NOTIFIED", 
        "Resolved": "RESOLVED",
        "Suppressed": "SUPPRESSED"
    }
    status = status_mapping.get(finding.get("status", "New"), "NEW")
    
    # Map record state - new format doesn't have explicit record state, derive from status
    record_state = "ACTIVE" if status in ["NEW", "NOTIFIED"] else "ARCHIVED"
    
    return FindingData(account, description, severity, title, finding_id, 
                      product_arn, resources, status, record_state, region)


def finding_parser(finding: Dict[str, Any], region: str = None) -> FindingData:
    """
    Parse finding from either legacy or new Security Hub event format.
    
    Args:
        finding: The finding object from the event
        region: AWS region (required for new format)
    
    Returns:
        FindingData object with parsed finding information
    """
    # Check if this is the new format by looking for specific fields
    if "finding_info" in finding and "cloud" in finding:
        logger.info("Parsing new Security Hub EventBridge finding format")
        return parse_new_finding(finding, region)
    else:
        logger.info("Parsing legacy Security Hub finding format")
        return parse_legacy_finding(finding)


def create_jira_ticket(jira_client: JIRA, project_key: str, issuetype_name: str, 
                      finding_data: FindingData) -> str:
    """
    Create a JIRA ticket for the given finding.
    
    Args:
        jira_client: JIRA client instance
        project_key: JIRA project key
        issuetype_name: JIRA issue type name
        finding_data: FindingData object containing finding information
    
    Returns:
        JIRA issue key
    """
    resources_str = "Resources: %s" % finding_data.resources if not "default" in finding_data.product_arn else ""

    new_issue = utils.create_ticket(
        jira_client, project_key, issuetype_name, finding_data.account, 
        finding_data.region or os.environ['AWS_REGION'], finding_data.description, 
        resources_str, finding_data.severity, finding_data.title, finding_data.finding_id)
    
    utils.update_securityhub(
        securityhub, finding_data.finding_id, finding_data.product_arn, 
        "NOTIFIED", f'JIRA Ticket: {new_issue}')
    
    utils.update_jira_assignee(jira_client, new_issue, finding_data.account)
    
    return new_issue


def should_auto_create_ticket(finding_data: FindingData) -> bool:
    """
    Determine if a ticket should be automatically created for this finding.
    Now captures ALL findings by default (removed config.json dependency).
    
    Args:
        finding_data: FindingData object containing finding information
    
    Returns:
        True if ticket should be auto-created, False otherwise
    """
    # Auto-create tickets for all findings that are NEW and ACTIVE
    return (finding_data.status == "NEW" and 
            finding_data.record_state == "ACTIVE" and
            finding_data.finding_id != "unknown")

def process_custom_action_event(event: Dict[str, Any], finding_data: FindingData, 
                               jira_client: JIRA, project_key: str, issuetype_name: str) -> None:
    """Process Security Hub Findings - Custom Action events."""
    action_name = event["detail"].get("actionName")
    
    if action_name == "CreateJiraIssue":
        if finding_data.status != "NEW":
            raise UserWarning(f"Finding workflow is not NEW: {finding_data.finding_id}")
        if finding_data.record_state != "ACTIVE":
            raise UserWarning(f"Finding is not ACTIVE: {finding_data.finding_id}")
        
        jira_issue = utils.get_jira_finding(
            jira_client, finding_data.finding_id, project_key, issuetype_name)
        
        if not jira_issue:
            logger.info(f"Creating ticket manually for {finding_data.finding_id}")
            create_jira_ticket(jira_client, project_key, issuetype_name, finding_data)
        else:
            logger.info(f"Finding {finding_data.finding_id} already reported in ticket {jira_issue}")
    else:
        logger.warning(f"Unknown custom action: {action_name}")


def process_imported_event(event: Dict[str, Any], finding_data: FindingData, 
                          jira_client: JIRA, project_key: str, issuetype_name: str) -> None:
    """Process Security Hub Findings - Imported events."""
    if finding_data.record_state == "ARCHIVED" and finding_data.status == "NOTIFIED":
        # Move to resolved
        jira_issue = utils.get_jira_finding(
            jira_client, finding_data.finding_id, project_key, issuetype_name)
        
        if jira_issue:
            utils.close_jira_issue(jira_client, jira_issue)
            utils.update_securityhub(securityhub, finding_data.finding_id, finding_data.product_arn, 
                                   "RESOLVED", f'Closed JIRA Ticket {jira_issue}')
    
    elif finding_data.record_state == "ACTIVE" and finding_data.status == "RESOLVED":
        # Reopen closed ticket as it was re-detected
        jira_issue = utils.get_jira_finding(
            jira_client, finding_data.finding_id, project_key, issuetype_name)
        
        if jira_issue and utils.is_closed(jira_client, jira_issue):
            utils.reopen_jira_issue(jira_client, jira_issue)
            utils.update_securityhub(securityhub, finding_data.finding_id, finding_data.product_arn, 
                                   "NOTIFIED", f'Reopening JIRA Ticket {jira_issue}')
    
    elif finding_data.record_state == "ACTIVE" and finding_data.status == "NEW" and should_auto_create_ticket(finding_data):
        # Auto-create ticket for new findings
        jira_issue = utils.get_jira_finding(
            jira_client, finding_data.finding_id, project_key, issuetype_name)
        
        if not jira_issue:
            logger.info(f"Creating ticket automatically for {finding_data.finding_id}")
            create_jira_ticket(jira_client, project_key, issuetype_name, finding_data)
    
    else:
        logger.info(f"Not performing any action for {finding_data.finding_id}")


def process_findings_imported_v2_event(event: Dict[str, Any], finding_data: FindingData, 
                                     jira_client: JIRA, project_key: str, issuetype_name: str) -> None:
    """Process new Findings Imported V2 events from EventBridge."""
    # For new format, we primarily handle NEW findings by auto-creating tickets
    if should_auto_create_ticket(finding_data):
        jira_issue = utils.get_jira_finding(
            jira_client, finding_data.finding_id, project_key, issuetype_name)
        
        if not jira_issue:
            logger.info(f"Creating ticket automatically for new finding {finding_data.finding_id}")
            create_jira_ticket(jira_client, project_key, issuetype_name, finding_data)
        else:
            logger.info(f"Finding {finding_data.finding_id} already has ticket {jira_issue}")
    else:
        logger.info(f"Not creating ticket for finding {finding_data.finding_id} - status: {finding_data.status}, record_state: {finding_data.record_state}")


def lambda_handler(event: Dict[str, Any], context: Any) -> None:
    """
    Main Lambda handler function.
    
    Args:
        event: EventBridge event containing Security Hub findings
        context: Lambda context object
    """
    try:
        utils.validate_environments(["JIRA_API_TOKEN", "AWS_REGION"])
        
        # Extract environment variables
        region = os.environ['AWS_REGION']
        project_key = os.environ['JIRA_PROJECT_KEY']
        issuetype_name = os.environ['JIRA_ISSUETYPE']
        jira_instance = os.environ['JIRA_INSTANCE']
        jira_credentials = os.environ.get("JIRA_API_TOKEN")

        # Get JIRA client
        jira_client = utils.get_jira_client(secretsmanager, jira_instance, jira_credentials)
        
        # Process each finding in the event
        findings = event.get("detail", {}).get("findings", [])
        if not findings:
            logger.warning("No findings found in event")
            return
        
        logger.info(f"Processing {len(findings)} findings from event type: {event.get('detail-type')}")
        
        for finding in findings:
            try:
                # Parse finding data
                finding_data = finding_parser(finding, region)
                logger.info(f"Processing finding: {finding_data.finding_id} - {finding_data.title}")
                
                # Route to appropriate handler based on event type
                detail_type = event.get("detail-type")
                
                if detail_type == "Security Hub Findings - Custom Action":
                    process_custom_action_event(event, finding_data, jira_client, project_key, issuetype_name)
                elif detail_type == "Security Hub Findings - Imported":
                    process_imported_event(event, finding_data, jira_client, project_key, issuetype_name)
                elif detail_type == "Findings Imported V2":
                    process_findings_imported_v2_event(event, finding_data, jira_client, project_key, issuetype_name)
                else:
                    logger.warning(f"Unknown event type: {detail_type}")
                    
            except UserWarning as e:
                logger.error(f"User warning for finding {finding.get('finding_info', {}).get('uid', 'unknown')}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error processing finding: {e}", exc_info=True)
                
    except Exception as e:
        logger.error(f"Fatal error in lambda_handler: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python security_hub_integration.py event.template")
        sys.exit(1)
    
    template = sys.argv[1]
    try:
        with open(template, "r") as event_file:
            security_hub_event = json.load(event_file)
            local_time = datetime.now(timezone.utc).astimezone().isoformat()
            
            # Update timestamps for legacy format findings
            for securityhub_finding in security_hub_event.get("detail", {}).get("findings", []):
                if "UpdatedAt" not in securityhub_finding:
                    securityhub_finding["UpdatedAt"] = local_time
            
            lambda_handler(security_hub_event, None)
    except FileNotFoundError:
        logger.error(f"Event template file not found: {template}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in event template: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error processing event template: {e}")
        sys.exit(1)
