import logging
import os
import hashlib
import base64
import re
import boto3
import json
from jira import JIRA, JIRAError
from botocore.exceptions import ClientError
import jira
from typing import Dict, List, Optional, Any, Union

logger = logging.getLogger('')

# Constants for JIRA status names
JIRA_STATUS_RESOLVED = "Resolved"
JIRA_STATUS_RISK_APPROVED = "Risk approved"
JIRA_STATUS_FALSE_POSITIVE = "Accepted false positive"
JIRA_STATUS_OPEN = "Open"
JIRA_STATUS_ALLOCATED = "Allocated for fix"
JIRA_STATUS_TEST_FIX = "Test fix"

# Constants for transitions
JIRA_TRANSITION_ALLOCATE = "Allocate for fix"
JIRA_TRANSITION_MARK_TESTING = "Mark for testing"
JIRA_TRANSITION_MARK_RESOLVED = "Mark as resolved"
JIRA_TRANSITION_REOPEN = "Reopen"


def validate_environments(envs: List[str]) -> None:
    """
    Validate that required environment variables are set.

    Args:
        envs: List of environment variable names to validate

    Raises:
        UserWarning: If any required environment variables are missing
    """
    undefined = []

    for env in envs:
        if env not in os.environ or not os.environ[env].strip():
            undefined.append(env)
            logger.error(f'Environment variable {env} not set or empty')

    if undefined:
        raise UserWarning(
            f"Missing environment variables: {', '.join(undefined)}"
        )


def assume_role(
    aws_account_number: str, 
    role_name: str, 
    external_id: Optional[str] = None
) -> Dict[str, Union[boto3.Session, str]]:
    """
    Assume the provided role in target account and return session details.

    Args:
        aws_account_number: AWS Account Number
        role_name: Role to assume in target account
        external_id: Optional external ID for role assumption

    Returns:
        Dictionary containing session and credential information

    Raises:
        ClientError: If role assumption fails
    """
    try:
        sts_client = boto3.client('sts')
        partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

        parameters = {
            "RoleArn": f'arn:{partition}:iam::{aws_account_number}:role/{role_name}',
            "RoleSessionName": "SecurityScanner"
        }

        if external_id:
            parameters["ExternalId"] = external_id

        response = sts_client.assume_role(**parameters)

        account_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )

        return {
            'session': account_session,
            'aws_access_key_id': response['Credentials']['AccessKeyId'],
            'aws_secret_access_key': response['Credentials']['SecretAccessKey'],
            'aws_session_token': response['Credentials']['SessionToken']
        }

    except ClientError as e:
        logger.error(f"Failed to assume role {role_name} in account {aws_account_number}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error assuming role: {str(e)}")
        raise


def update_unassigned_ticket(jira_client: JIRA, issue: Any, message: str) -> None:
    """
    Update a JIRA ticket that couldn't be assigned to a specific user.
    
    Args:
        jira_client: JIRA client instance
        issue: JIRA issue object
        message: Message to add as comment
    """
    try:
        default_assignee = os.environ.get("JIRA_DEFAULT_ASSIGNEE")
        if default_assignee:
            jira_client.assign_issue(issue, default_assignee)
