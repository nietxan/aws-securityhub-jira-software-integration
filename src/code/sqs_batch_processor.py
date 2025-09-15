import os
import json
import time
import logging
import boto3
from jira import JIRA, JIRAError
import utils

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler())

sqs = boto3.client('sqs')
secretsmanager = boto3.client('secretsmanager')


def backoff_sleep(attempt: int, retry_after: float | None = None):
    if retry_after:
        time.sleep(min(float(retry_after), 30))
        return
    delay = min(2 ** attempt, 30)
    time.sleep(delay)


def drain_messages(queue_url: str, max_batches: int = 30):
    batches = 0
    while batches < max_batches:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=10,
            VisibilityTimeout=120,
        )
        messages = resp.get('Messages', [])
        if not messages:
            break
        yield messages
        batches += 1


def process_record(jira_client: JIRA, record: dict, project_key: str, issuetype_name: str):
    # Use utils.create_ticket with parent/subtask grouping
    resources_str = "Resources: %s" % record.get('resources', [])
    utils.create_ticket(
        jira_client,
        project_key,
        issuetype_name,
        record.get('account'),
        record.get('region'),
        record.get('description'),
        resources_str,
        record.get('severity'),
        record.get('title'),
        record.get('finding_id'),
    )


def lambda_handler(event, context):
    utils.validate_environments(["JIRA_API_TOKEN", "AWS_REGION"]) 

    queue_url = os.environ['FINDINGS_QUEUE_URL']
    jira_instance = os.environ['JIRA_INSTANCE']
    jira_credentials = os.environ.get("JIRA_API_TOKEN")
    project_key = os.environ['JIRA_PROJECT_KEY']
    issuetype_name = os.environ['JIRA_ISSUETYPE']

    jira_client = utils.get_jira_client(secretsmanager, jira_instance, jira_credentials)

    attempt = 0
    for messages in drain_messages(queue_url):
        entries_to_delete = []
        for m in messages:
            body = json.loads(m['Body'])
            try:
                process_record(jira_client, body, project_key, issuetype_name)
                entries_to_delete.append({
                    'Id': m['MessageId'],
                    'ReceiptHandle': m['ReceiptHandle']
                })
            except JIRAError as je:
                status = getattr(je, 'status_code', None)
                retry_after = None
                try:
                    retry_after = je.response.headers.get('Retry-After') if je.response else None
                except Exception:
                    pass
                if status == 429 or status == 503:
                    logger.warning(f"JIRA rate limit/availability error, backing off: {je}")
                    backoff_sleep(attempt, retry_after)
                    attempt += 1
                    # do not delete; message will be retried
                else:
                    logger.error(f"Permanent JIRA error, dropping message: {je}")
                    entries_to_delete.append({
                        'Id': m['MessageId'],
                        'ReceiptHandle': m['ReceiptHandle']
                    })
            except Exception as e:
                logger.error(f"Unexpected error processing message: {e}", exc_info=True)
                # leave message for retry

        if entries_to_delete:
            sqs.delete_message_batch(QueueUrl=queue_url, Entries=entries_to_delete)


