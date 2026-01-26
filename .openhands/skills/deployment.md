---
triggers:
- deploy
- cdk deploy
- deployment
---

# AWS CDK Deployment Guidelines

When deploying this infrastructure:

## Pre-deployment Checklist

1. Ensure AWS credentials are configured
2. Run `npm run build` to verify TypeScript compilation
3. Run `npm run test` to ensure all tests pass
4. Review `config/config.toml` for environment-specific settings

## Deployment Commands

```bash
# Deploy all stacks
npx cdk deploy --all

# Deploy specific stack
npx cdk deploy NetworkStack
npx cdk deploy AuthStack
npx cdk deploy ComputeStack

# Deploy with approval prompts
npx cdk deploy --all --require-approval broadening
```

## Stack Dependencies

Deploy in this order (based on CDK dependencies in `bin/openhands-infra.ts`):

1. NetworkStack (VPC, subnets)
2. MonitoringStack (CloudWatch, S3) - no dependencies
3. AuthStack (Cognito) - no dependencies, can deploy in parallel
4. SecurityStack (IAM, WAF) - depends on NetworkStack and MonitoringStack
5. DatabaseStack (RDS) - depends on NetworkStack and SecurityStack
6. ComputeStack (ECS) - depends on NetworkStack, SecurityStack, MonitoringStack, and DatabaseStack
7. EdgeStack (CloudFront) - depends on ComputeStack and AuthStack

Note: `npx cdk deploy --all` handles dependency ordering automatically.

## Post-deployment Verification

1. Check CloudFormation console for stack status
2. Verify ECS services are running
3. Test CloudFront distribution endpoint
4. Monitor CloudWatch logs for errors
