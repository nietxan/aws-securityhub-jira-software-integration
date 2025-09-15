import logging
import os
import hashlib
import base64
import re
import boto3
import json
from jira import JIRA, JIRAError
from botocore.exceptions import ClientError
from typing import Optional, List, Any, Dict
import jira

logger = logging.getLogger('')


def validate_environments(envs):
    undefined = []

    for env in envs:
        is_defined = env in os.environ
        if not is_defined:
            undefined.append(env)
            logger.error('Environment variable %s not set', env)
    if len(undefined) > 0:
        raise UserWarning(
                "Missing environment variables: {}".format(",".join(undefined)))


def assume_role(aws_account_number, role_name, external_id=None):
    """
    Assumes the provided role in each account and returns a GuardDuty client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    """
    sts_client = boto3.client('sts')
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    parameters = {"RoleArn": 'arn:{}:iam::{}:role/{}'.format(
        partition,
        aws_account_number,
        role_name,
        ), "RoleSessionName": "SecurityScanner"}

    if external_id:
        parameters["ExternalId"] = external_id
    response = sts_client.assume_role(**parameters)

    account_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'])

    session = {}
    session['session'] = account_session
    session['aws_access_key_id'] = response['Credentials']['AccessKeyId']
    session['aws_secret_access_key'] = response['Credentials']['SecretAccessKey']
    session['aws_session_token'] = response['Credentials']['SessionToken']
    return session


def update_unassigned_ticket(jira_client, issue, message):
    jira_client.assign_issue(issue, os.environ.get("JIRA_DEFAULT_ASSIGNEE"))
    issue.fields.labels.append("aws-sec-not-assigned")
    issue.update(fields={"labels": issue.fields.labels})
    jira_client.add_comment(issue, message)


def get_account_organization_tags(account):
    org_id = os.environ.get("ORG_ACCOUNT_ID")
    org_role = os.environ.get("ORG_ROLE")
    external_id = os.environ.get("EXTERNAL_ID")
    if org_role:
        session = assume_role(org_id, org_role, external_id)['session']
        org_client = session.client('organizations')
        tags = org_client.list_tags_for_resource(ResourceId=account)
        return tags
    return {}

# assign ticket based on Organization account


def update_jira_assignee(jira_client, issue, account):
    tags = get_account_organization_tags(account)
    merged_tags = {}
    for tag in tags['Tags']:
        merged_tags[tag['Key']] = tag['Value']
    if merged_tags.get("SecurityContactID"):
        assignee = merged_tags.get("SecurityContactID")
        try:
            jira_client.assign_issue(issue, assignee)
        except JIRAError:
            logger.warning("User {0} couldn't be assigned to {1}".format(
                assignee, jira_client))
            message = "Security responsible not in JIRA\n Id: {0}".format(
                    assignee)
            update_unassigned_ticket(jira_client, issue, message)
    else:
        logger.info("Account owner could not be identified {0} - {1}".format(account,issue))
        message = "Account owner could not be identified"
        update_unassigned_ticket(jira_client, issue, message)


def get_finding_id_from(jira_ticket):
    if jira_ticket is None or jira_ticket.fields.description is None:
        logger.warning("The jira_ticket or its description is None, cannot extract finding ID.")
        return None

    description = jira_ticket.fields.description
    # Searching for regex in description
    matched = re.search(
            'Id%3D%255Coperator%255C%253AEQUALS%255C%253A([a-zA-Z0-9\\.\\-\\_\\:\\/]+)', description)
    return matched.group(1) if matched and matched.group(1) else None


def get_finding_id_from_subtask(jira_ticket):
    """
    Extract finding ID from subtask description or labels.
    """
    if jira_ticket is None or jira_ticket.fields.description is None:
        logger.warning("The subtask or its description is None, cannot extract finding ID.")
        return None

    description = jira_ticket.fields.description
    # Search for finding ID in subtask description
    matched = re.search(
            'Id%3D%255Coperator%255C%253AEQUALS%255C%253A([a-zA-Z0-9\\.\\-\\_\\:\\/]+)', description)
    return matched.group(1) if matched and matched.group(1) else None


def get_jira_client(secretsmanager_client,jira_instance,jira_credentials_secret):
    region = os.environ['AWS_REGION']
    jira_credentials = get_secret(secretsmanager_client, jira_credentials_secret, region)
    auth_type = jira_credentials['auth']
    jira_client = None
    if auth_type == "basic_auth":
        jira_client=JIRA("https://"+jira_instance, basic_auth=(jira_credentials['email'], jira_credentials['token']))
    else:
        jira_client=JIRA(jira_instance, token_auth=jira_credentials['token'])

    return jira_client


def get_finding_digest(finding_id):
    m = hashlib.md5()  # nosec
    m.update(finding_id.encode("utf-8"))
    one_way_digest = m.hexdigest()
    return one_way_digest


def get_title_digest(title):
    m = hashlib.md5()  # nosec
    m.update(title.strip().lower().encode("utf-8"))
    return m.hexdigest()


def get_jira_finding(jira_client, finding_id,project_key, issuetype_name):
    digest = get_finding_digest(finding_id)
    created_before = jira_client.search_issues(
            'Project = {0} AND issuetype = "{1}" AND (labels = finding-{2})'.format(project_key, issuetype_name,digest))
    # Should only exist once
    return created_before[0] if len(created_before) > 0 else None


def get_jira_latest_updated_findings(jira_client,project_key, issuetype_name):
    return jira_client.search_issues('Project = {0} AND issuetype = "{1}" AND updated  >= -2w'.format(project_key, issuetype_name), maxResults=False)


def get_jira_issue_by_title(jira_client, project_key, issuetype_name, title):
    """
    Find an existing JIRA issue by normalized title label to enable grouping.
    """
    # Extract the short description part (after CVE - )
    title_parts = title.split(' - ', 1)
    short_description = title_parts[1].strip() if len(title_parts) > 1 else title

    # First try by label digest
    title_digest = get_title_digest(short_description)
    jql_by_label = 'Project = {0} AND issuetype = "{1}" AND labels = title-{2}'.format(project_key, issuetype_name, title_digest)
    issues = jira_client.search_issues(jql_by_label)
    if len(issues) > 0:
        return issues[0]

    # Fallback: search by summary text to dedupe older parents created before label change
    safe_summary = short_description.replace('"', '\\"')
    jql_by_summary = 'Project = {0} AND issuetype = "{1}" AND summary ~ "{2}"'.format(project_key, issuetype_name, safe_summary)
    issues = jira_client.search_issues(jql_by_summary)
    return issues[0] if len(issues) > 0 else None


def add_label_if_missing(jira_client, issue, label):
    labels = list(issue.fields.labels or [])
    if label not in labels:
        labels.append(label)
        issue.update(fields={"labels": labels})


def map_severity_to_priority_name(severity: str) -> str:
    """
    Map incoming SecurityHub/Inspector severity to a valid JIRA priority name.
    Allows overrides via env vars; falls back to sensible defaults.
    """
    sev = (severity or "").strip().lower()
    # Environment overrides
    critical = os.environ.get("JIRA_PRIORITY_CRITICAL", "Highest")
    high = os.environ.get("JIRA_PRIORITY_HIGH", "High")
    medium = os.environ.get("JIRA_PRIORITY_MEDIUM", "Medium")
    low = os.environ.get("JIRA_PRIORITY_LOW", "Low")
    default_p = os.environ.get("JIRA_PRIORITY_DEFAULT", high)

    if sev == "critical":
        return critical
    if sev == "high":
        return high
    if sev == "medium":
        return medium
    if sev == "low":
        return low
    return default_p


def get_existing_cve_subtask(jira_client, parent_issue, cve, account):
    """
    Check if a CVE subtask already exists for the given CVE and account under the parent issue.
    """
    try:
        # Search for subtasks of the parent with matching CVE and account labels
        jql = 'parent = {} AND labels = cve-{} AND labels = account-{}'.format(
            str(parent_issue), cve.lower(), account)
        subtasks = jira_client.search_issues(jql)
        return subtasks[0] if len(subtasks) > 0 else None
    except Exception as e:
        logger.warning("Error searching for existing CVE subtask: {}".format(e))
        return None


def update_subtask_resources(jira_client, subtask, new_resources, finding_id_text):
    """
    Update an existing subtask with new resources reference.
    """
    try:
        # Add a comment with the new resources
        comment = """ *New Resources Detected*
        Resources: {}
        
        FindingId: {}
        """.format(new_resources, finding_id_text)
        
        jira_client.add_comment(subtask, comment)
        logger.info("Updated subtask {} with new resources".format(subtask))
    except Exception as e:
        logger.error("Failed to update subtask resources: {}".format(e))


# creates ticket based on the Security Hub finding
def create_ticket(jira_client, project_key, issuetype_name, account, region, description, resources, severity, title, id):
    digest = get_finding_digest(id)
    
    title_parts = title.split(' - ', 1)
    cve = title_parts[0].strip() if len(title_parts) > 0 else "UNKNOWN"
    short_description = title_parts[1].strip() if len(title_parts) > 1 else title
    # IMPORTANT: compute title digest from the normalized short description (not full title)
    title_digest = get_title_digest(short_description)

    # Prefer plain FindingId reference rather than console link (more portable)
    finding_id_text = id
    
    # Check if parent issue exists for this title
    parent_issue = get_jira_issue_by_title(jira_client, project_key, issuetype_name, short_description)
    has_cve = cve.upper().startswith('CVE')
    
    if parent_issue:
        # If the title does not include a CVE, attach details to the parent and return
        if not has_cve:
            try:
                comment = (
                    "New occurrence (no CVE).\n"
                    "Title: {0}\n"
                    "Account: {1}\n"
                    "Severity: {2}\n"
                    "Description: {3}\n"
                    "FindingId: {4}"
                ).format(short_description, account, severity, description, finding_id_text)
                jira_client.add_comment(parent_issue, comment)
                add_label_if_missing(jira_client, parent_issue, "no-cve")
                return str(parent_issue)
            except Exception as e:
                logger.error("Failed to update parent for no-CVE finding: %s", e, exc_info=True)
                return str(parent_issue)
        # Parent exists - check if CVE subtask already exists
        logger.info("Found existing parent issue {} for title '{}', checking for existing CVE subtask".format(parent_issue, short_description))
        
        # Check if CVE subtask already exists
        existing_cve_subtask = get_existing_cve_subtask(jira_client, parent_issue, cve, account)
        
        if existing_cve_subtask:
            # Update existing subtask with new resources
            logger.info("Found existing CVE subtask {} for CVE {}, updating resources".format(existing_cve_subtask, cve))
            update_subtask_resources(jira_client, existing_cve_subtask, resources, finding_id_text)
            return str(existing_cve_subtask)
        else:
            # Create new CVE subtask
            try:
                subtask_dict = {
                    "project": {"key": project_key},
                    "issuetype": {"name": "Subtask"},
                    "parent": {"key": str(parent_issue)},
                    "summary": "CVE: {} - Account: {}".format(cve, account),
                    "labels": ["cve", "cve-{}".format(cve.lower()), "account-{}".format(account), "severity-{}".format(severity.lower())],
                    "priority": {"name": map_severity_to_priority_name(severity)},
                    "description": """ *CVE Details*
                    CVE: {}
                    Account: {}
                    
                    {}
                    
                    FindingId: {}
                    """.format(cve, account, description, finding_id_text)
                }
                try:
                    subtask = jira_client.create_issue(fields=subtask_dict)
                except JIRAError as je1:
                    # Try alternative common subtask type spelling if configured instance uses it
                    subtask_dict["issuetype"] = {"name": "Sub-task"}
                    subtask = jira_client.create_issue(fields=subtask_dict)
                logger.info("Successfully created CVE subtask {} for parent {}".format(subtask, parent_issue))
                return str(subtask)
            except Exception as e:
                logger.error("Failed to create CVE subtask for {}: {}".format(cve, e), exc_info=True)
                return None
    else:
        # No parent exists - create parent issue for this title
        logger.info("No parent issue found for title '{}', creating parent issue".format(short_description))
        
        if not has_cve:
            # Create a standalone parent with all details when no CVE part is present
            parent_dict = {
                "project": {"key": project_key},
                "issuetype": {"name": issuetype_name},  
                "summary": "{} ({})".format(short_description, account),
                "labels": ["security-finding", "title-{}".format(title_digest), "no-cve", "severity-{}".format((severity or '').lower())],
                "priority": {"name": map_severity_to_priority_name(severity)},
                "description": """ *Finding Details*
                Title: {}
                Account: {}
                Severity: {}
                Resources: {}
                
                {}
                
                FindingId: {}
                """.format(short_description, account, severity, resources, description, finding_id_text)
            }
            parent_issue = jira_client.create_issue(fields=parent_dict)
            logger.info("Created parent-only issue {} for title '{}' (no CVE)".format(parent_issue, short_description))
            return str(parent_issue)
        else:
            parent_dict = {
                "project": {"key": project_key},
                "issuetype": {"name": issuetype_name},  
                "summary": "{} - Security Finding Group".format(short_description),
                "labels": ["security-finding", "title-{}".format(title_digest), "grouped-finding"],
                "priority": {"name": map_severity_to_priority_name(severity)},
                "description": """ *Security Finding Group*
                
                Multiple CVEs may be associated with this finding type.
                Check subtasks for specific CVE details and affected resources.
                """
            }
            parent_issue = jira_client.create_issue(fields=parent_dict)
            logger.info("Created parent issue {} for title '{}'".format(parent_issue, short_description))
        
        # Now create the first CVE subtask
        try:
            subtask_dict = {
                "project": {"key": project_key},
                "issuetype": {"name": "Subtask"},
                "parent": {"key": str(parent_issue)},
                "summary": "{} - Account: {}".format(cve, account),
                "labels": ["{}".format(cve.lower()), "account-{}".format(account), "severity-{}".format(severity.lower())],
                "priority": {"name": map_severity_to_priority_name(severity)},
                "description": """ *CVE Details*
                CVE: {}
                Account: {}
                
                {}
                
                FindingId: {}
                """.format(cve, account, description, finding_id_text)
            }
            try:
                subtask = jira_client.create_issue(fields=subtask_dict)
            except JIRAError as je2:
                subtask_dict["issuetype"] = {"name": "Sub-task"}
                subtask = jira_client.create_issue(fields=subtask_dict)
            logger.info("Successfully created CVE subtask {} for new parent {}".format(subtask, parent_issue))
            return str(subtask)
        except Exception as e:
            logger.error("Failed to create CVE subtask for {}: {}".format(cve, e), exc_info=True)
            return str(parent_issue)


def comment_with_new_resources(jira_client, issue, account, region, description, resources, severity, title, finding_id):
    """
    Add a comment to an existing grouped ticket noting newly affected resources and link.
    """
    finding_link = "https://{0}.console.aws.amazon.com/securityhub/home?region={0}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A{1}".format(
            region, finding_id)
    resources_str = resources if isinstance(resources, str) else ", ".join(resources or [])
    
    # Split title for better formatting
    title_parts = title.split(' - ', 1)
    cve = title_parts[0].strip() if len(title_parts) > 0 else "UNKNOWN"
    short_description = title_parts[1].strip() if len(title_parts) > 1 else title
    
    comment = (
        "New occurrence of Security Hub finding detected.\n"
        "CVE: {0}\n"
        "Description: {1}\n"
        "Severity: {2}\n"
        "Account: {3}\n"
        "Resources: {4}\n"
        "Description: {5}\n\n"
        "[Link to Security Hub finding|{6}]"
    ).format(cve, short_description, severity, account, resources_str, description, finding_link)
    jira_client.add_comment(issue, comment)
    # ensure title label exists
    add_label_if_missing(jira_client, issue, "title-%s" % get_title_digest(title))


def update_securityhub(securityhub_client, id, product_arn, status, note):
    try:
        response = securityhub_client.batch_update_findings(
                FindingIdentifiers=[
                    {'Id':  id,
                     'ProductArn': product_arn
                     }],
                Workflow={'Status': status}, Note={
                        'Text': note,
                        'UpdatedBy': 'security-hub-integration'
                })
        if response.get('FailedFindings'):
            for element in response['FailedFindings']:
                logger.error("Update error - FindingId {0}".format(element["Id"]))
                logger.error(
                        "Update error - ErrorCode {0}".format(element["ErrorCode"]))
                logger.error(
                        "Update error - ErrorMessage {0}".format(element["ErrorMessage"]))
        return response
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code')
        if code == 'InvalidAccessException':
            logger.warning("Security Hub update skipped: account not subscribed or inaccessible for finding %s", id)
            return None
        logger.error("Security Hub update failed for finding %s: %s", id, e)
        raise


def is_closed(jira_client, issue):
    """Check if issue is in a closed/resolved state."""
    closed_statuses = ["Resolved", "Closed", "Done"]
    return issue.fields.status.name in closed_statuses


def reopen_jira_issue(jira_client, issue):
    """Reopen a closed JIRA issue."""
    try:
        jira_client.transition_issue(issue, 'Reopen')
        logger.info("Reopened issue {}".format(issue))
    except Exception as e:
        logger.warning("Failed to reopen issue {}: {}".format(issue, e))


def close_jira_issue(jira_client, issue):
    """Close a JIRA issue."""
    try:
        jira_client.transition_issue(issue, "Mark as resolved", comment="Resolved automatically by security-hub-integration")
        logger.info("Closed issue {}".format(issue))
    except Exception as e:
        logger.warning("Failed to close issue {}: {}".format(issue, e))


def get_secret(client, secret_arn, region_name):

    secret = None
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_arn
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(
                get_secret_value_response['SecretBinary'])
    return json.loads(secret)
