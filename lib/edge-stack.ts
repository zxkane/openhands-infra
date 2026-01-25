import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53Targets from 'aws-cdk-lib/aws-route53-targets';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import { Construct } from 'constructs';
import { OpenHandsConfig, ComputeStackOutput, AuthStackOutput } from './interfaces.js';
import * as fs from 'fs';
import * as path from 'path';

export interface EdgeStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  computeOutput?: ComputeStackOutput;
  alb: elbv2.IApplicationLoadBalancer;
  /** Required - provides Cognito configuration from AuthStack */
  authOutput: AuthStackOutput;
}

/**
 * EdgeStack - Combined Auth and CDN infrastructure (us-east-1)
 *
 * This stack must be deployed to us-east-1 for Lambda@Edge and CloudFront certificates.
 *
 * Components:
 * - Cognito User Pool for user authentication
 * - Lambda@Edge function for JWT validation
 * - ACM certificate for CloudFront
 * - CloudFront distribution with VPC Origin
 * - WAF WebACL with managed rules
 * - Route 53 alias record
 */
export class EdgeStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: EdgeStackProps) {
    super(scope, id, props);

    const { config, alb, computeOutput } = props;
    const fullDomain = `${config.subDomain}.${config.domainName}`;
    const runtimeDomain = `runtime.${fullDomain}`; // e.g., runtime.{subdomain}.{domain}

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
      subjectAlternativeNames: [`*.${runtimeDomain}`], // *.runtime.{subdomain}.{domain}
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // ========================================
    // Cognito (from AuthStack output)
    // ========================================

    // AuthStack provides Cognito configuration via authOutput prop
    const { authOutput } = props;
    if (!authOutput) {
      throw new Error('EdgeStack requires authOutput from AuthStack');
    }
    const userPoolId = authOutput.userPoolId;
    const userPoolClientId = authOutput.userPoolClientId;
    const userPoolDomainPrefix = authOutput.userPoolDomainPrefix;
    const clientSecretName = authOutput.clientSecretName;

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

    // Lambda@Edge function with proper JWKS signature verification
    // Load auth handler from external file for unit testing coverage
    // Note: Lambda@Edge cannot access regional services, so config is embedded at deploy time
    const authHandlerPath = path.join(__dirname, 'lambda-edge', 'auth-handler.js');
    let authHandlerCode = fs.readFileSync(authHandlerPath, 'utf-8');

    // Replace placeholders with actual config values
    // SECURITY NOTE: Cookie domain set to base domain for runtime subdomain access
    // This allows auth cookies to work on both main domain and *.runtime.{subdomain}.{domain}
    authHandlerCode = authHandlerCode
      .replace(/'\{\{USER_POOL_ID\}\}'/g, `'${userPoolId}'`)
      .replace(/'\{\{CLIENT_ID\}\}'/g, `'${userPoolClientId}'`)
      .replace(/'\{\{CLIENT_SECRET\}\}'/g, `'{{resolve:secretsmanager:${clientSecretName}:SecretString}}'`)
      .replace(/'\{\{COGNITO_DOMAIN\}\}'/g, `'${userPoolDomainPrefix}.auth.${authOutput.region}.amazoncognito.com'`)
      .replace(/'\{\{JWKS_URI\}\}'/g, `'https://cognito-idp.${authOutput.region}.amazonaws.com/${userPoolId}/.well-known/jwks.json'`)
      .replace(/'\{\{ISSUER\}\}'/g, `'https://cognito-idp.${authOutput.region}.amazonaws.com/${userPoolId}'`)
      .replace(/'\{\{REGION\}\}'/g, `'${authOutput.region}'`)
      .replace(/'\{\{COOKIE_DOMAIN\}\}'/g, `'.${config.domainName}'`);

    const authFunction = new lambda.Function(this, 'AuthFunction', {
      runtime: lambda.Runtime.NODEJS_22_X,
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
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
// Origin Response Handler - adds security headers for runtime requests
// and prevents caching of HTML files to ensure patches are always fresh
exports.handler = async (event) => {
  const response = event.Records[0].cf.response;
  const request = event.Records[0].cf.request;
  const host = request.headers.host ? request.headers.host[0].value : '';
  const uri = request.uri || '';
  const contentType = response.headers['content-type'] ? response.headers['content-type'][0].value : '';

  // Prevent caching of HTML files to ensure patches are always fresh
  // This is important for the patched index.html with auto-resume functionality
  const isHtmlRequest = uri === '/' || uri.endsWith('.html') ||
    uri.startsWith('/conversations') || uri.startsWith('/settings') ||
    contentType.includes('text/html');

  if (isHtmlRequest && !host.includes('.runtime.')) {
    response.headers['cache-control'] = [{
      key: 'Cache-Control',
      value: 'no-cache, no-store, must-revalidate'
    }];
    response.headers['pragma'] = [{ key: 'Pragma', value: 'no-cache' }];
    response.headers['expires'] = [{ key: 'Expires', value: '0' }];
  }

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
    // Origin verification header prevents direct ALB access bypassing CloudFront/WAF
    const originVerifySecret = computeOutput?.originVerifySecret ?? 'fallback-secret';
    const httpOrigin = new origins.HttpOrigin(alb.loadBalancerDnsName, {
      protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
      readTimeout: cdk.Duration.seconds(60),
      keepaliveTimeout: cdk.Duration.seconds(60),
      customHeaders: {
        'X-Origin-Verify': originVerifySecret,
      },
    });

    // Response Headers Policy for CORS support
    // Required because the origin sets access-control-allow-credentials but not access-control-allow-origin
    const responseHeadersPolicy = new cloudfront.ResponseHeadersPolicy(this, 'CorsHeadersPolicy', {
      responseHeadersPolicyName: `OpenHands-CORS-${fullDomain.replace(/\./g, '-')}-${this.account}`,
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
        fullDomain,                  // {subdomain}.{domain} (main app)
        `*.${runtimeDomain}`,        // *.runtime.{subdomain}.{domain} (runtime subdomains)
      ],
      certificate: certificate,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      webAclId: webAcl.attrArn,
      defaultBehavior: {
        origin: httpOrigin,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
        responseHeadersPolicy: responseHeadersPolicy,
        edgeLambdas: [
          {
            eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
            functionVersion: authFunctionVersion,
            includeBody: false,
          },
          {
            eventType: cloudfront.LambdaEdgeEventType.ORIGIN_RESPONSE,
            functionVersion: securityHeadersFunctionVersion,
            includeBody: false,
          },
        ],
      },
      // Runtime proxy behavior for path-based routing (/runtime/{conv_id}/{port}/...)
      // This is used for WebSocket connections to agent-server (sockets/events)
      // which require authentication via the main domain cookie
      additionalBehaviors: {
        '/runtime/*': {
          origin: httpOrigin,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
          responseHeadersPolicy: responseHeadersPolicy,
          // Add Lambda@Edge to verify JWT and inject X-Cognito-User-Id header
          // This is required for OpenResty to authorize runtime requests
          edgeLambdas: [
            {
              eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
              functionVersion: authFunctionVersion,
              includeBody: false,
            },
          ],
        },
      },
    });

    // ========================================
    // Route 53 DNS Records
    // ========================================

    // Main domain record: {subdomain}.{domain}
    new route53.ARecord(this, 'AliasRecord', {
      zone: hostedZone,
      recordName: config.subDomain,
      target: route53.RecordTarget.fromAlias(
        new route53Targets.CloudFrontTarget(distribution)
      ),
    });

    // Runtime wildcard record: *.runtime.{subdomain}.{domain}
    new route53.ARecord(this, 'RuntimeWildcardRecord', {
      zone: hostedZone,
      recordName: `*.runtime.${config.subDomain}`,
      target: route53.RecordTarget.fromAlias(
        new route53Targets.CloudFrontTarget(distribution)
      ),
    });

    // ========================================
    // CloudFormation Outputs
    // ========================================

    new cdk.CfnOutput(this, 'DistributionId', {
      value: distribution.distributionId,
      description: 'CloudFront Distribution ID',
    });

    new cdk.CfnOutput(this, 'DistributionDomainName', {
      value: distribution.distributionDomainName,
      description: 'CloudFront Distribution Domain Name',
    });

    new cdk.CfnOutput(this, 'SiteUrl', {
      value: `https://${fullDomain}`,
      description: 'OpenHands Application URL',
    });

    new cdk.CfnOutput(this, 'WebAclArn', {
      value: webAcl.attrArn,
      description: 'WAF WebACL ARN',
    });

  }
}
