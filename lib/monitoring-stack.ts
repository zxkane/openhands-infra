import * as cdk from 'aws-cdk-lib';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as backup from 'aws-cdk-lib/aws-backup';
import * as events from 'aws-cdk-lib/aws-events';
import { Construct } from 'constructs';
import { OpenHandsConfig, MonitoringStackOutput } from './interfaces.js';

export interface MonitoringStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
}

/**
 * MonitoringStack - Creates CloudWatch Logs, Alarms, and AWS Backup
 *
 * This stack sets up:
 * - CloudWatch Log Groups for application logs
 * - CloudWatch Alarms for key metrics
 * - AWS Backup plan for EBS snapshots
 */
export class MonitoringStack extends cdk.Stack {
  public readonly output: MonitoringStackOutput;

  constructor(scope: Construct, id: string, props: MonitoringStackProps) {
    super(scope, id, props);

    const { config } = props;

    // CloudWatch Log Group for OpenHands application
    const appLogGroup = new logs.LogGroup(this, 'AppLogGroup', {
      logGroupName: '/openhands/application',
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // SNS Topic for alerts
    const alertTopic = new sns.Topic(this, 'AlertTopic', {
      displayName: 'OpenHands Alerts',
    });

    // S3 Bucket for OpenHands data persistence (conversations, settings, events)
    const dataBucket = new s3.Bucket(this, 'DataBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      lifecycleRules: [
        {
          id: 'CleanupOldVersions',
          noncurrentVersionExpiration: cdk.Duration.days(30),
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
      ],
    });

    // CloudWatch Dashboard - basic dashboard created here, ASG-specific alarms added in ComputeStack
    const dashboard = new cloudwatch.Dashboard(this, 'OpenHandsDashboard', {
      dashboardName: 'OpenHands-Monitoring',
    });

    // Add header widget - ASG-specific alarm widgets will be added in ComputeStack
    dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# OpenHands Monitoring Dashboard\n\nASG-specific alarms are managed by the Compute stack.',
        width: 24,
        height: 2,
      }),
    );

    // AWS Backup Plan for EBS snapshots
    const backupPlan = new backup.BackupPlan(this, 'OpenHandsBackupPlan', {
      backupPlanName: 'OpenHands-Daily-Backup',
    });

    // Add backup rule: daily backup, retain for 14 days (2 weeks)
    backupPlan.addRule(new backup.BackupPlanRule({
      ruleName: 'DailyBackup',
      scheduleExpression: events.Schedule.cron({
        hour: '3',
        minute: '0',
      }),
      deleteAfter: cdk.Duration.days(14),
      startWindow: cdk.Duration.hours(1),
      completionWindow: cdk.Duration.hours(2),
    }));

    // Tag-based selection for backup (EBS volumes with tag backup=true)
    backupPlan.addSelection('OpenHandsBackupSelection', {
      backupSelectionName: 'OpenHands-EBS-Selection',
      resources: [
        backup.BackupResource.fromTag('backup', 'true'),
      ],
    });

    // Store outputs
    this.output = {
      appLogGroup,
      alertTopic,
      dataBucket,
    };

    // CloudFormation outputs
    new cdk.CfnOutput(this, 'LogGroupName', {
      value: appLogGroup.logGroupName,
      description: 'CloudWatch Log Group Name',
    });

    new cdk.CfnOutput(this, 'AlertTopicArn', {
      value: alertTopic.topicArn,
      description: 'SNS Alert Topic ARN',
    });

    new cdk.CfnOutput(this, 'DashboardUrl', {
      value: `https://${config.region}.console.aws.amazon.com/cloudwatch/home?region=${config.region}#dashboards:name=OpenHands-Monitoring`,
      description: 'CloudWatch Dashboard URL',
    });

    new cdk.CfnOutput(this, 'DataBucketName', {
      value: dataBucket.bucketName,
      description: 'S3 Bucket for OpenHands data persistence',
    });
  }
}
