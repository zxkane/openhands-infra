import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53Targets from 'aws-cdk-lib/aws-route53-targets';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import { OpenHandsConfig, AuthStackOutput } from './interfaces.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface EdgeStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  authOutput: AuthStackOutput;
}

/**
 * EdgeStack - CDN + edge auth enforcement (us-east-1)
 *
 * This stack must be deployed to us-east-1 for Lambda@Edge and CloudFront certificates.
 *
 * Components:
 * - Lambda@Edge function for JWT validation
 * - ACM certificate for CloudFront
 * - CloudFront distribution with VPC Origin
 * - WAF WebACL with managed rules
 * - Route 53 alias record
 */
export class EdgeStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: EdgeStackProps) {
    super(scope, id, props);

    const { config, authOutput } = props;

    // Read ALB DNS name and origin secret from SSM parameters written by ComputeStack
    // This avoids CDK cross-region reference issues when multiple Edge stacks share the same Compute stack
    const albDnsName = ssm.StringParameter.valueForStringParameter(
      this,
      '/openhands/compute/alb-dns-name'
    );
    const originVerifySecret = ssm.StringParameter.valueForStringParameter(
      this,
      '/openhands/compute/origin-verify-secret'
    );
    const fullDomain = `${config.subDomain}.${config.domainName}`;
    const runtimeDomain = `runtime.${fullDomain}`; // e.g., runtime.openhands.test.kane.mx

    // ========================================
    // Route 53 & Certificate
    // ========================================

    // Import existing Route 53 Hosted Zone
    const hostedZone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
      hostedZoneId: config.hostedZoneId,
      zoneName: config.domainName,
    });

    // ACM Certificate for CloudFront (must be in us-east-1)
    // Includes both main domain and runtime wildcard as SAN
    const certificate = new acm.Certificate(this, 'Certificate', {
      domainName: fullDomain,
      subjectAlternativeNames: [`*.${runtimeDomain}`], // *.runtime.openhands.test.kane.mx
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // ========================================
    // Cognito (AuthStack)
    // ========================================
    // User pool, client, and managed login branding are provisioned in AuthStack and reused
    // by multiple EdgeStack deployments (one per environment/domain).

    // ========================================
    // Lambda@Edge for Authentication
    // ========================================

    const authFunctionRole = new iam.Role(this, 'AuthFunctionRole', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // Load Lambda@Edge auth handler from external file for testability
    // Replace placeholders with actual config values at synth time
    const authHandlerPath = path.join(__dirname, 'lambda-edge', 'auth-handler.js');
    let authHandlerCode = fs.readFileSync(authHandlerPath, 'utf8');

    // Strip the module.exports section (used only for testing)
    authHandlerCode = authHandlerCode.replace(/\/\/ Export functions for testing[\s\S]*$/, '');

    // Replace CONFIG placeholders with actual values
    authHandlerCode = authHandlerCode
      .replace("'{{USER_POOL_ID}}'", `'${authOutput.userPoolId}'`)
      .replace("'{{CLIENT_ID}}'", `'${authOutput.userPoolClientId}'`)
      .replace("'{{CLIENT_SECRET}}'", `'{{resolve:secretsmanager:${authOutput.clientSecretName}:SecretString}}'`)
      .replace("'{{COGNITO_DOMAIN}}'", `'${authOutput.userPoolDomainPrefix}.auth.${authOutput.region}.amazoncognito.com'`)
      .replace("'{{JWKS_URI}}'", `'https://cognito-idp.${authOutput.region}.amazonaws.com/${authOutput.userPoolId}/.well-known/jwks.json'`)
      .replace("'{{ISSUER}}'", `'https://cognito-idp.${authOutput.region}.amazonaws.com/${authOutput.userPoolId}'`)
      .replace("'{{REGION}}'", `'${authOutput.region}'`)
      // SECURITY NOTE: Cookie domain set to base domain for runtime subdomain access
      // This allows auth cookies to work on both main domain and *.runtime.{subdomain}.{domain}
      // The broader scope is REQUIRED for runtime functionality - restricting to .{subdomain}.{domain}
      // would break access to runtime subdomains. WAF and Lambda@Edge provide additional protection.
      .replace("'{{COOKIE_DOMAIN}}'", `'.${config.domainName}'`);

    // Lambda@Edge function with proper JWKS signature verification
    const authFunction = new lambda.Function(this, 'AuthFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(authHandlerCode),
      role: authFunctionRole,
      timeout: cdk.Duration.seconds(5),
      memorySize: 128,
    });

    // Create version for Lambda@Edge
    const authFunctionVersion = authFunction.currentVersion;

    // ========================================
    // Lambda@Edge for Runtime Security Headers
    // ========================================

    const securityHeadersFunctionRole = new iam.Role(this, 'SecurityHeadersFunctionRole', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // Lambda@Edge function for origin-response - adds security headers for runtime requests
    const securityHeadersFunction = new lambda.Function(this, 'SecurityHeadersFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
// Origin Response Handler - adds security headers for runtime requests
exports.handler = async (event) => {
  const response = event.Records[0].cf.response;
  const request = event.Records[0].cf.request;
  const host = request.headers.host ? request.headers.host[0].value : '';

  // Check if this is a runtime request (runtime subdomain)
  if (host.includes('.runtime.')) {
    const headers = response.headers;

    // Security headers - protect against cross-runtime attacks
    headers['x-frame-options'] = [{ key: 'X-Frame-Options', value: 'SAMEORIGIN' }];
    headers['x-content-type-options'] = [{ key: 'X-Content-Type-Options', value: 'nosniff' }];
    headers['x-xss-protection'] = [{ key: 'X-XSS-Protection', value: '1; mode=block' }];
    headers['referrer-policy'] = [{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }];
    headers['content-security-policy'] = [{
      key: 'Content-Security-Policy',
      value: "frame-ancestors 'self'; default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:;"
    }];

    // Cookie security - rewrite Set-Cookie headers for isolation
    if (headers['set-cookie']) {
      headers['set-cookie'] = headers['set-cookie'].map(cookie => {
        let value = cookie.value;
        // Remove any Domain attribute (ensures cookie only valid for exact host)
        value = value.replace(/;\\s*Domain=[^;]*/gi, '');
        // Add Secure attribute if not present
        if (!/;\\s*Secure/i.test(value)) {
          value += '; Secure';
        }
        // Add SameSite=Strict if not present
        if (!/;\\s*SameSite/i.test(value)) {
          value += '; SameSite=Strict';
        }
        return { key: 'Set-Cookie', value };
      });
    }
  }

  return response;
};
`),
      role: securityHeadersFunctionRole,
      timeout: cdk.Duration.seconds(5),
      memorySize: 128,
    });

    // Create version for Lambda@Edge
    const securityHeadersFunctionVersion = securityHeadersFunction.currentVersion;

    // ========================================
    // WAF WebACL
    // ========================================

    const webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
      defaultAction: { allow: {} },
      scope: 'CLOUDFRONT',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'OpenHandsWebAcl',
        sampledRequestsEnabled: true,
      },
      rules: [
        // AWS Managed Rules - Common Rule Set
        {
          name: 'AWSManagedRulesCommonRuleSet',
          priority: 1,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
              // Override SizeRestrictions_BODY rule to COUNT instead of BLOCK
              // OpenHands runtime API needs to send large payloads (50KB+) for conversation creation
              ruleActionOverrides: [
                {
                  name: 'SizeRestrictions_BODY',
                  actionToUse: { count: {} },
                },
              ],
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesCommonRuleSet',
            sampledRequestsEnabled: true,
          },
        },
        // AWS Managed Rules - Known Bad Inputs
        {
          name: 'AWSManagedRulesKnownBadInputsRuleSet',
          priority: 2,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesKnownBadInputsRuleSet',
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesKnownBadInputsRuleSet',
            sampledRequestsEnabled: true,
          },
        },
        // Rate limiting rule - 50000 requests per 5 minutes per IP (increased for automated testing)
        {
          name: 'RateLimitRule',
          priority: 3,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              limit: 50000,
              aggregateKeyType: 'IP',
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: 'RateLimitRule',
            sampledRequestsEnabled: true,
          },
        },
      ],
    });

    // ========================================
    // CloudFront Distribution with HTTP Origin
    // ========================================

    // Note: CloudFront VPC Origin does NOT support WebSocket connections.
    // We use internet-facing ALB with HttpOrigin to support WebSocket.
    //
    // Security: ALB requires X-Origin-Verify header for origin verification.
    // This prevents direct access to ALB bypassing CloudFront.
    // ALB DNS name and origin secret are passed as strings to avoid cross-region CDK reference issues.
    const httpOrigin = new origins.HttpOrigin(albDnsName, {
      protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
      readTimeout: cdk.Duration.seconds(60),
      keepaliveTimeout: cdk.Duration.seconds(60),
      customHeaders: {
        'X-Origin-Verify': originVerifySecret,
      },
    });

    // Response Headers Policy for CORS support
    // Required because the origin sets access-control-allow-credentials but not access-control-allow-origin
    // Include domain in name to support multiple Edge stacks in the same account
    const domainSuffix = config.domainName.replace(/\./g, '-');
    const responseHeadersPolicy = new cloudfront.ResponseHeadersPolicy(this, 'CorsHeadersPolicy', {
      responseHeadersPolicyName: `OpenHands-CORS-${domainSuffix}-${this.account}`,
      comment: 'Adds CORS headers for credentialed requests',
      corsBehavior: {
        accessControlAllowCredentials: true,
        accessControlAllowOrigins: [`https://${fullDomain}`],
        accessControlAllowMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE'],
        accessControlAllowHeaders: [
          'Accept',
          'Accept-Language',
          'Content-Language',
          'Content-Type',
          'Authorization',
          'Cache-Control',
          'Pragma',
          'Origin',
          'X-Requested-With',
        ],
        accessControlExposeHeaders: [
          'Content-Length',
          'Content-Type',
          'ETag',
          'Cache-Control',
        ],
        accessControlMaxAge: cdk.Duration.seconds(86400),
        originOverride: true,
      },
    });

    // CloudFront Distribution
    // Includes both main domain and runtime wildcard
    const distribution = new cloudfront.Distribution(this, 'Distribution', {
      comment: 'OpenHands CloudFront Distribution',
      domainNames: [
        fullDomain,                  // openhands.test.kane.mx (main app)
        `*.${runtimeDomain}`,        // *.runtime.openhands.test.kane.mx (runtime subdomains)
      ],
      certificate: certificate,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      webAclId: webAcl.attrArn,
      defaultBehavior: {
        origin: httpOrigin,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
        responseHeadersPolicy: responseHeadersPolicy,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        edgeLambdas: [
          {
            functionVersion: authFunctionVersion,
            eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
          },
          {
            functionVersion: securityHeadersFunctionVersion,
            eventType: cloudfront.LambdaEdgeEventType.ORIGIN_RESPONSE,
          },
        ],
      },
    });

    // ========================================
    // Route 53 Records
    // ========================================

    // A record for main domain (keep 'AliasRecord' ID for backwards compatibility)
    new route53.ARecord(this, 'AliasRecord', {
      zone: hostedZone,
      recordName: config.subDomain,
      target: route53.RecordTarget.fromAlias(new route53Targets.CloudFrontTarget(distribution)),
    });

    // Wildcard A record for runtime subdomains (keep 'RuntimeWildcardRecord' ID for backwards compatibility)
    // *.runtime.{subdomain}.{domain} → CloudFront
    new route53.ARecord(this, 'RuntimeWildcardRecord', {
      zone: hostedZone,
      recordName: `*.runtime.${config.subDomain}`,
      target: route53.RecordTarget.fromAlias(new route53Targets.CloudFrontTarget(distribution)),
    });

    // ========================================
    // Outputs
    // ========================================

    new cdk.CfnOutput(this, 'DistributionDomainName', {
      value: distribution.distributionDomainName,
    });

    new cdk.CfnOutput(this, 'SiteUrl', {
      value: `https://${fullDomain}`,
    });
  }
}
