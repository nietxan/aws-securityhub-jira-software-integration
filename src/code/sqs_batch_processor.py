import os
import json
import time
import logging
import boto3
from jira import JIRA, JIRAError
import utils

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
# Ensure root logger emits INFO so logs from utils.py are visible
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(logging.StreamHandler())

sqs = boto3.client('sqs')
secretsmanager = boto3.client('secretsmanager')


def backoff_sleep(attempt: int, retry_after: float | None = None):
    if retry_after:
        time.sleep(min(float(retry_after), 30))
        return
    delay = min(2 ** attempt, 30)
    time.sleep(delay)


def drain_messages(queue_url: str, max_batches: int = None, time_budget_s: int = None):
    batches = 0
    start = time.time()
    while batches < max_batches:
        if time_budget_s is not None and (time.time() - start) >= time_budget_s:
            logger.info("Time budget reached, stopping drain")
            break
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            VisibilityTimeout=60,
        )
        messages = resp.get('Messages', [])
        if not messages:
            break
        logger.info("Drained batch %s with %s messages", batches + 1, len(messages))
        yield messages
        batches += 1


def process_record(jira_client: JIRA, record: dict, project_key: str, issuetype_name: str):
    # Use utils.create_ticket with parent/subtask grouping
    resources = record.get('resources', [])
    resources_str = "Resources: %s" % resources
    title = record.get('title') or ""
    title_parts = title.split(' - ', 1)
    cve = title_parts[0].strip() if len(title_parts) > 0 else "UNKNOWN"
    short_title = title_parts[1].strip() if len(title_parts) > 1 else title
    logger.info(
        "Processing record: finding_id=%s account=%s severity=%s title='%s' short_title='%s' cve='%s' resources=%s",
        record.get('finding_id'), record.get('account'), record.get('severity'), title, short_title, cve, len(resources)
    )
    utils.create_ticket(
        jira_client,
        project_key,
        issuetype_name,
        record.get('account'),
        record.get('region'),
        record.get('description'),
        resources_str,
        record.get('severity'),
        title,
        record.get('finding_id'),
    )


def lambda_handler(event, context):
    utils.validate_environments(["JIRA_API_TOKEN", "AWS_REGION"]) 

    queue_url = os.environ['FINDINGS_QUEUE_URL']
    jira_instance = os.environ['JIRA_INSTANCE']
    jira_credentials = os.environ.get("JIRA_API_TOKEN")
    project_key = os.environ['JIRA_PROJECT_KEY']
    issuetype_name = os.environ['JIRA_ISSUETYPE']

    logger.info("Batch processor start: queue=%s project=%s issuetype=%s", queue_url, project_key, issuetype_name)
    jira_client = utils.get_jira_client(secretsmanager, jira_instance, jira_credentials)

    attempt = 0
    total_processed = 0
    total_deleted = 0
    total_retried = 0
    total_dropped = 0
    max_batches = int(os.environ.get('BATCH_MAX_BATCHES', '200'))
    time_budget = int(os.environ.get('BATCH_TIME_BUDGET_SECONDS', '840'))
    for messages in drain_messages(queue_url, max_batches=max_batches, time_budget_s=time_budget):
        entries_to_delete = []
        for m in messages:
            body = json.loads(m['Body'])
            try:
                process_record(jira_client, body, project_key, issuetype_name)
                entries_to_delete.append({
                    'Id': m['MessageId'],
                    'ReceiptHandle': m['ReceiptHandle']
                })
                total_deleted += 1
            except JIRAError as je:
                status = getattr(je, 'status_code', None)
                retry_after = None
                try:
                    retry_after = je.response.headers.get('Retry-After') if je.response else None
                except Exception:
                    pass
                if status == 429 or status == 503:
                    logger.warning("JIRA rate limit/availability error for message %s, backing off: %s", m.get('MessageId'), je)
                    backoff_sleep(attempt, retry_after)
                    attempt += 1
                    # do not delete; message will be retried
                    total_retried += 1
                else:
                    logger.error("Permanent JIRA error for message %s, dropping: %s", m.get('MessageId'), je)
                    entries_to_delete.append({
                        'Id': m['MessageId'],
                        'ReceiptHandle': m['ReceiptHandle']
                    })
                    total_dropped += 1
            except Exception as e:
                logger.error("Unexpected error processing message %s: %s", m.get('MessageId'), e, exc_info=True)
                # leave message for retry
                total_retried += 1
            finally:
                total_processed += 1

        if entries_to_delete:
            sqs.delete_message_batch(QueueUrl=queue_url, Entries=entries_to_delete)
            logger.info("Deleted %s messages from SQS", len(entries_to_delete))

    logger.info(
        "Batch processor summary: processed=%s deleted=%s retried=%s dropped=%s attempts=%s",
        total_processed, total_deleted, total_retried, total_dropped, attempt
    )


