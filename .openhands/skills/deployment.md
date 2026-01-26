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

Deploy in this order:
1. NetworkStack (VPC, subnets)
2. SecurityStack (IAM, WAF)
3. AuthStack (Cognito)
4. DatabaseStack (RDS)
5. ComputeStack (ECS)
6. EdgeStack (CloudFront)
7. MonitoringStack (CloudWatch)

## Post-deployment Verification

1. Check CloudFormation console for stack status
2. Verify ECS services are running
3. Test CloudFront distribution endpoint
4. Monitor CloudWatch logs for errors
