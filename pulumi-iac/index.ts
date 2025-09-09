
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
    runtime: aws.lambda.Runtime.Python3d11,
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
        },
    },
});

// Create the Lambda function to refresh Security Hub findings from JIRA.
const refreshJiraSecHubFunction = new aws.lambda.Function("RefreshJIRASecHubFunction", {
    functionName: `securityhub-jira-refresh-${environment}`,
    description: "Update findings in Security Hub according to JIRA changes",
    runtime: aws.lambda.Runtime.Python3d11,
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

// Create a CloudWatch Events rule to trigger the JIRA Security Hub function.
const jiraSecHubCwRule = new aws.cloudwatch.EventRule("JIRASecHubCWRule", {
    name: `securityhub-change-status-${environment}`,
    description: "This CW rule helps keep Security Hub in sync with JIRA updates",
    eventPattern: JSON.stringify({
        "source": [
            "aws.securityhub"
        ],
        "detail-type": [
            "Security Hub Findings - Custom Action",
            "Security Hub Findings - Imported"
        ]
    }),
});

// Create a CloudWatch Events target for the JIRA Security Hub function.
new aws.cloudwatch.EventTarget("JIRASecHubCWTarget", {
    rule: jiraSecHubCwRule.name,
    arn: jiraSecHubFunction.arn,
});

// Grant the CloudWatch Events rule permission to invoke the Lambda function.
new aws.lambda.Permission("PermissionForEventsToInvokeIntegrationLambda", {
    action: "lambda:InvokeFunction",
    function: jiraSecHubFunction.name,
    principal: "events.amazonaws.com",
    sourceArn: jiraSecHubCwRule.arn,
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
