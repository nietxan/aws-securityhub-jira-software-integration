
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as path from "path";

// Create a new Pulumi project for the AWS Security Hub JIRA integration.
// This project will create the necessary AWS resources to integrate Security Hub with JIRA.

// Configuration variables
const config = new pulumi.Config();
const environment = config.get("environment") || "prod";
const organizationAccessRole = config.get("organizationAccessRole") || "OrganizationsReadOnlyAccess";
const organizationAccessExternalId = config.get("organizationAccessExternalId") || "";
const organizationManagementAccountId = config.require("organizationManagementAccountId");
const jiraDefaultAssignee = config.require("jiraDefaultAssignee");
const jiraInstance = config.require("jiraInstance");
const jiraProjectKey = config.require("jiraProjectKey");
const jiraIssueType = config.require("jiraIssueType");
const scheduleExpression = config.get("scheduleExpression") || "rate(1 day)";

// Create a secret to store the JIRA API token.
const jiraApiTokenSecret = new aws.secretsmanager.Secret("JiraAPIToken", {
    name: `JiraAPIToken-${environment}`,
    description: "JIRA API Token",
});

// Create an IAM role for the Lambda function that imports findings from Security Hub to JIRA.
const lambdaImportRole = new aws.iam.Role("LambdaImportRole", {
    description: "Lambda role for importing findings from Security Hub to JIRA",
    assumeRolePolicy: {
        Version: "2012-10-17",
        Statement: [{
            Action: "sts:AssumeRole",
            Effect: "Allow",
            Principal: {
                Service: "lambda.amazonaws.com",
            },
        }],
    },
});

// SQS queue to buffer findings for batch processing
const findingsQueue = new aws.sqs.Queue("FindingsQueue", {
    name: `securityhub-jira-findings-${environment}`,
    visibilityTimeoutSeconds: 300,
});

// Queue resource policy (matches CloudFormation template semantics)
new aws.sqs.QueuePolicy("QueueAccessPolicy", {
    queueUrl: findingsQueue.url,
    policy: pulumi.all([findingsQueue.arn]).apply(([queueArn]) => JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                Effect: "Allow",
                Principal: { Service: "lambda.amazonaws.com" },
                Action: [
                    "sqs:SendMessage",
                    "sqs:SendMessageBatch",
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:DeleteMessageBatch",
                    "sqs:GetQueueAttributes",
                ],
                Resource: queueArn,
            },
        ],
    })),
});

// Attach a policy to the Lambda import role.
new aws.iam.RolePolicy("LambdaImportRolePolicy", {
    role: lambdaImportRole.id,
    policy: {
        Version: "2012-10-17",
        Statement: [
            {
                Action: [
                    "securityhub:BatchImportFindings",
                    "securityhub:UpdateFindings",
                    "securityhub:BatchUpdateFindings",
                    "securityhub:GetFindings",
                ],
                Effect: "Allow",
                Resource: "*",
            },
            {
                Action: [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                Effect: "Allow",
                Resource: "*",
            },
            {
                Action: [
                    "sqs:SendMessage",
                    "sqs:SendMessageBatch",
                    "sqs:GetQueueAttributes",
                ],
                Effect: "Allow",
                Resource: findingsQueue.arn,
            },
            {
                Action: "sts:AssumeRole",
                Effect: "Allow",
                Resource: `arn:aws:iam::*:role/${organizationAccessRole}`,
            },
            {
                Action: [
                    "secretsmanager:GetResourcePolicy",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecretVersionIds",
                ],
                Effect: "Allow",
                Resource: jiraApiTokenSecret.arn,
            },
        ],
    },
});

// Create an IAM role for the Lambda function that refreshes findings in JIRA and Security Hub.
const lambdaRefreshRole = new aws.iam.Role("LambdaRefreshRole", {
    description: "Lambda role for refreshing findings in JIRA and Security Hub",
    assumeRolePolicy: {
        Version: "2012-10-17",
        Statement: [{
            Action: "sts:AssumeRole",
            Effect: "Allow",
            Principal: {
                Service: "lambda.amazonaws.com",
            },
        }],
    },
});

// Attach a policy to the Lambda refresh role.
new aws.iam.RolePolicy("LambdaRefreshRolePolicy", {
    role: lambdaRefreshRole.id,
    policy: {
        Version: "2012-10-17",
        Statement: [
            {
                Action: [
                    "securityhub:BatchImportFindings",
                    "securityhub:UpdateFindings",
                    "securityhub:BatchUpdateFindings",
                    "securityhub:GetFindings",
                ],
                Effect: "Allow",
                Resource: "*",
            },
            {
                Action: [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                Effect: "Allow",
                Resource: "*",
            },
            {
                Action: [
                    "secretsmanager:GetResourcePolicy",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecretVersionIds",
                ],
                Effect: "Allow",
                Resource: jiraApiTokenSecret.arn,
            },
        ],
    },
});

// Create the Lambda function to import Security Hub findings to JIRA.
const jiraSecHubFunction = new aws.lambda.Function("JIRASecHubFunction", {
    functionName: `securityhub-jira-lambda-import-${environment}`,
    description: "Lambda integrates Security Hub to JIRA",
    runtime: aws.lambda.Runtime.Python3d12,
    handler: "security_hub_integration.lambda_handler",
    role: lambdaImportRole.arn,
    timeout: 300,
    code: new pulumi.asset.AssetArchive({
        ".": new pulumi.asset.FileArchive("../src/code"),
    }),
    environment: {
        variables: {
            JIRA_API_TOKEN: jiraApiTokenSecret.id,
            ORG_ACCOUNT_ID: organizationManagementAccountId,
            ORG_ROLE: organizationAccessRole,
            EXTERNAL_ID: organizationAccessExternalId,
            JIRA_DEFAULT_ASSIGNEE: jiraDefaultAssignee,
            JIRA_ISSUETYPE: jiraIssueType,
            JIRA_PROJECT_KEY: jiraProjectKey,
            JIRA_INSTANCE: jiraInstance,
            FINDINGS_QUEUE_URL: findingsQueue.url,
        },
    },
});

// Create the Lambda function to refresh Security Hub findings from JIRA.
const refreshJiraSecHubFunction = new aws.lambda.Function("RefreshJIRASecHubFunction", {
    functionName: `securityhub-jira-refresh-${environment}`,
    description: "Update findings in Security Hub according to JIRA changes",
    runtime: aws.lambda.Runtime.Python3d12,
    handler: "sync_securityhub.lambda_handler",
    role: lambdaRefreshRole.arn,
    timeout: 300,
    code: new pulumi.asset.AssetArchive({
        ".": new pulumi.asset.FileArchive("../src/code"),
    }),
    environment: {
        variables: {
            JIRA_API_TOKEN: jiraApiTokenSecret.id,
            JIRA_INSTANCE: jiraInstance,
            JIRA_ISSUETYPE: jiraIssueType,
            JIRA_PROJECT_KEY: jiraProjectKey,
        },
    },
});

// EventBridge rule (Legacy) - route only HIGH/CRITICAL legacy findings
const jiraSecHubCwRuleLegacy = new aws.cloudwatch.EventRule("JIRASecHubCWRuleLegacy", {
    name: `securityhub-change-status-legacy-${environment}`,
    description: "This rule routes only HIGH/CRITICAL legacy Security Hub findings to Lambda",
    eventPattern: JSON.stringify({
        source: ["aws.securityhub"],
        "detail-type": [
            "Security Hub Findings - Custom Action",
            "Security Hub Findings - Imported",
        ],
        detail: {
            findings: {
                Severity: {
                    Label: ["HIGH", "CRITICAL"],
                },
            },
        },
    }),
});
new aws.cloudwatch.EventTarget("JIRASecHubCWTargetLegacy", {
    rule: jiraSecHubCwRuleLegacy.name,
    arn: jiraSecHubFunction.arn,
});
new aws.lambda.Permission("PermissionForEventsToInvokeIntegrationLambdaLegacy", {
    action: "lambda:InvokeFunction",
    function: jiraSecHubFunction.name,
    principal: "events.amazonaws.com",
    sourceArn: jiraSecHubCwRuleLegacy.arn,
});

// EventBridge rule (V2) - Findings Imported V2 for High/Critical
const jiraSecHubCwRuleV2 = new aws.cloudwatch.EventRule("JIRASecHubCWRuleV2", {
    name: `securityhub-change-status-v2-${environment}`,
    description: "This rule routes only High/Critical Findings Imported V2 to Lambda",
    eventPattern: JSON.stringify({
        source: ["aws.securityhub"],
        "detail-type": ["Findings Imported V2"],
        detail: {
            findings: {
                severity: ["High", "Critical"],
            },
        },
    }),
});
new aws.cloudwatch.EventTarget("JIRASecHubCWTargetV2", {
    rule: jiraSecHubCwRuleV2.name,
    arn: jiraSecHubFunction.arn,
});
new aws.lambda.Permission("PermissionForEventsToInvokeIntegrationLambdaV2", {
    action: "lambda:InvokeFunction",
    function: jiraSecHubFunction.name,
    principal: "events.amazonaws.com",
    sourceArn: jiraSecHubCwRuleV2.arn,
});

// Create a CloudWatch Events rule to trigger the refresh JIRA Security Hub function.
const refreshJiraSecHubCwRule = new aws.cloudwatch.EventRule("RefreshJIRASecHubCWRule", {
    name: `securityhub-jira-refresh-${environment}`,
    description: "Keep Security Hub findings in sync with JIRA updates",
    scheduleExpression: scheduleExpression,
});

// Create a CloudWatch Events target for the refresh JIRA Security Hub function.
new aws.cloudwatch.EventTarget("RefreshJIRASecHubCWTarget", {
    rule: refreshJiraSecHubCwRule.name,
    arn: refreshJiraSecHubFunction.arn,
});

// Grant the CloudWatch Events rule permission to invoke the Lambda function.
new aws.lambda.Permission("PermissionForEventsToInvokeRefreshLambda", {
    action: "lambda:InvokeFunction",
    function: refreshJiraSecHubFunction.name,
    principal: "events.amazonaws.com",
    sourceArn: refreshJiraSecHubCwRule.arn,
});

// Create an SNS topic for CloudWatch alarms.
const alarmSnsTopic = new aws.sns.Topic("AlarmSNSTopic", {
    name: `securityhub-jira-alarm-topic-${environment}`,
    kmsMasterKeyId: "alias/aws/sns",
});

// Create a CloudWatch alarm for the import Lambda function.
new aws.cloudwatch.MetricAlarm("CloudWatchAlarmImport", {
    alarmDescription: "Lambda Critical Error Alarm for Security Hub -> JIRA integration",
    actionsEnabled: true,
    alarmActions: [alarmSnsTopic.arn],
    metricName: "Errors",
    namespace: "AWS/Lambda",
    statistic: "Sum",
    dimensions: {
        FunctionName: jiraSecHubFunction.name,
    },
    period: 300,
    evaluationPeriods: 1,
    datapointsToAlarm: 1,
    threshold: 1,
    comparisonOperator: "GreaterThanThreshold",
    treatMissingData: "notBreaching",
});

// Create a CloudWatch alarm for the refresh Lambda function.
new aws.cloudwatch.MetricAlarm("CloudWatchAlarmRefresh", {
    alarmDescription: "Lambda Critical Error Alarm for JIRA -> Security Hub integration",
    actionsEnabled: true,
    alarmActions: [alarmSnsTopic.arn],
    metricName: "Errors",
    namespace: "AWS/Lambda",
    statistic: "Sum",
    dimensions: {
        FunctionName: refreshJiraSecHubFunction.name,
    },
    period: 300,
    evaluationPeriods: 1,
    datapointsToAlarm: 1,
    threshold: 1,
    comparisonOperator: "GreaterThanThreshold",
    treatMissingData: "notBreaching",
});

// Batch Processor IAM role
const batchProcessorRole = new aws.iam.Role("BatchProcessorRole", {
    description: "Lambda role for batch processing findings from SQS to JIRA",
    assumeRolePolicy: {
        Version: "2012-10-17",
        Statement: [{
            Effect: "Allow",
            Principal: { Service: "lambda.amazonaws.com" },
            Action: "sts:AssumeRole",
        }],
    },
});

new aws.iam.RolePolicy("BatchProcessorRolePolicy", {
    role: batchProcessorRole.id,
    policy: pulumi.all([findingsQueue.arn, jiraApiTokenSecret.arn]).apply(([queueArn, secretArn]) => JSON.stringify({
        Statement: [
            {
                Effect: "Allow",
                Action: [
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:DeleteMessageBatch",
                    "sqs:GetQueueAttributes",
                ],
                Resource: queueArn,
            },
            {
                Effect: "Allow",
                Action: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                Resource: "*",
            },
            {
                Effect: "Allow",
                Action: [
                    "secretsmanager:GetResourcePolicy",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecretVersionIds",
                ],
                Resource: secretArn,
            },
        ],
        Version: "2012-10-17",
    })),
});

// Batch Processor Lambda
const batchProcessorFunction = new aws.lambda.Function("BatchProcessorFunction", {
    functionName: `securityhub-jira-batch-${environment}`,
    description: "Drain SQS and create/update JIRA tickets with rate-limit backoff",
    handler: "sqs_batch_processor.lambda_handler",
    role: batchProcessorRole.arn,
    runtime: aws.lambda.Runtime.Python3d12,
    timeout: 900,
    reservedConcurrentExecutions: 2,
    code: new pulumi.asset.AssetArchive({
        ".": new pulumi.asset.FileArchive("../src/code"),
    }),
    environment: {
        variables: {
            JIRA_API_TOKEN: jiraApiTokenSecret.id,
            JIRA_INSTANCE: jiraInstance,
            JIRA_ISSUETYPE: jiraIssueType,
            JIRA_PROJECT_KEY: jiraProjectKey,
            FINDINGS_QUEUE_URL: findingsQueue.url,
            BATCH_MAX_BATCHES: "400",
            BATCH_TIME_BUDGET_SECONDS: "840",
        },
    },
});

// Scheduler role to invoke batch processor
const schedulerInvokeRole = new aws.iam.Role("SchedulerInvokeRole", {
    assumeRolePolicy: {
        Version: "2012-10-17",
        Statement: [{
            Effect: "Allow",
            Principal: { Service: "scheduler.amazonaws.com" },
            Action: "sts:AssumeRole",
        }],
    },
});

new aws.iam.RolePolicy("SchedulerInvokeRolePolicy", {
    role: schedulerInvokeRole.id,
    policy: batchProcessorFunction.arn.apply((arn) => JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Effect: "Allow",
            Action: "lambda:InvokeFunction",
            Resource: arn,
        }],
    })),
});

// EventBridge Scheduler schedule to invoke the batch processor every 5 minutes
new aws.scheduler.Schedule("BatchSchedule", {
    name: `securityhub-jira-batch-${environment}`,
    scheduleExpression: "rate(5 minutes)",
    flexibleTimeWindow: { mode: "FLEXIBLE", maximumWindowInMinutes: 1 },
    target: {
        arn: batchProcessorFunction.arn,
        roleArn: schedulerInvokeRole.arn,
    },
});
