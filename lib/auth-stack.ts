import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { OpenHandsConfig, AuthStackOutput } from './interfaces.js';

export interface AuthStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  /**
   * Full domains that are allowed as OAuth callback/logout domains.
   * Example: ["openhands.example.com", "openhands.test.example.com"]
   */
  callbackDomains: string[];
  /**
   * Suffix to keep Cognito domain prefix unique and avoid collisions with legacy stacks.
   * Final prefix becomes: openhands-${accountId}-${domainPrefixSuffix}
   */
  domainPrefixSuffix?: string;
  /**
   * Secret name to store the app client secret for Lambda@Edge token exchange.
   * Defaults to: openhands/cognito-client-secret-${domainPrefixSuffix}
   */
  clientSecretName?: string;
}

export class AuthStack extends cdk.Stack {
  public readonly output: AuthStackOutput;

  constructor(scope: Construct, id: string, props: AuthStackProps) {
    super(scope, id, props);

    const cognitoSiteName = props.config.siteName ?? 'Openhands on AWS';

    const callbackDomains = Array.from(new Set(props.callbackDomains))
      .map(d => d.trim())
      .filter(Boolean);
    if (callbackDomains.length === 0) {
      throw new Error('AuthStack requires at least one callback domain in callbackDomains');
    }

    // ========================================
    // Cognito User Pool
    // ========================================

    const userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: cognitoSiteName,
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      autoVerify: { email: true },
      standardAttributes: {
        email: { required: true, mutable: true },
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: { sms: false, otp: true },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Cognito Domain
    const domainPrefixSuffix = (props.domainPrefixSuffix ?? 'shared').trim() || 'shared';
    const domainPrefix = `openhands-${cdk.Aws.ACCOUNT_ID}-${domainPrefixSuffix}`;
    const userPoolDomain = userPool.addDomain('CognitoDomain', {
      cognitoDomain: { domainPrefix },
    });

    // Switch hosted pages to Managed Login (v2).
    const cfnUserPoolDomain = userPoolDomain.node.defaultChild as cognito.CfnUserPoolDomain;
    cfnUserPoolDomain.managedLoginVersion = 2;

    const callbackUrls = callbackDomains.map(d => `https://${d}/_callback`);
    const logoutUrls = callbackDomains.map(d => `https://${d}/`);

    const userPoolClient = userPool.addClient('WebAppClient', {
      userPoolClientName: cognitoSiteName,
      generateSecret: true,
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
        ],
        callbackUrls,
        logoutUrls,
      },
      authFlows: { userPassword: true, userSrp: true },
      preventUserExistenceErrors: true,
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
      accessTokenValidity: cdk.Duration.hours(1),
      idTokenValidity: cdk.Duration.days(1),
      refreshTokenValidity: cdk.Duration.days(30),
    });

    // ========================================
    // Cognito Managed Login (v2) Branding
    // ========================================

    const readAssetBase64 = (assetPathFromRepoRoot: string) => {
      const absolutePath = path.join(__dirname, '..', assetPathFromRepoRoot);
      return fs.readFileSync(absolutePath).toString('base64');
    };

    const openHandsColors = {
      base: '0d0f11ff',
      baseSecondary: '24272eff',
      input: '393939ff',
      border: '3c3c4aff',
      text: 'ecedeeff',
      textMuted: 'c4cbdaff',
      textMuted2: '9099acff',
      primary: 'c9b974ff',
      primaryHover: 'cfb755ff',
    };

    const managedLoginSettings = {
      categories: {
        auth: {
          authMethodOrder: [
            [
              {
                display: 'INPUT',
                type: 'USERNAME_PASSWORD',
              },
            ],
          ],
          federation: { interfaceStyle: 'BUTTON_LIST', order: [] },
        },
        form: {
          displayGraphics: true,
          instructions: { enabled: false },
          languageSelector: { enabled: false },
          location: { horizontal: 'CENTER', vertical: 'CENTER' },
          sessionTimerDisplay: 'NONE',
        },
        global: {
          colorSchemeMode: 'DARK',
          pageFooter: { enabled: false },
          pageHeader: { enabled: false },
          spacingDensity: 'REGULAR',
        },
      },
      componentClasses: {
        buttons: { borderRadius: 10.0 },
        focusState: {
          darkMode: { borderColor: openHandsColors.primary },
          lightMode: { borderColor: openHandsColors.primary },
        },
        input: {
          borderRadius: 10.0,
          darkMode: {
            defaults: {
              backgroundColor: openHandsColors.input,
              borderColor: openHandsColors.border,
            },
            placeholderColor: openHandsColors.textMuted2,
          },
          lightMode: {
            defaults: {
              backgroundColor: 'ffffffff',
              borderColor: openHandsColors.border,
            },
            placeholderColor: openHandsColors.textMuted2,
          },
        },
        inputLabel: {
          darkMode: { textColor: openHandsColors.textMuted },
          lightMode: { textColor: '111827ff' },
        },
        inputDescription: {
          darkMode: { textColor: openHandsColors.textMuted2 },
          lightMode: { textColor: '4b5563ff' },
        },
        link: {
          darkMode: {
            defaults: { textColor: openHandsColors.primary },
            hover: { textColor: openHandsColors.primaryHover },
          },
          lightMode: {
            defaults: { textColor: openHandsColors.primary },
            hover: { textColor: openHandsColors.primaryHover },
          },
        },
      },
      components: {
        favicon: { enabledTypes: ['SVG'] },
        form: {
          backgroundImage: { enabled: false },
          borderRadius: 12.0,
          darkMode: {
            backgroundColor: openHandsColors.baseSecondary,
            borderColor: openHandsColors.border,
          },
          lightMode: {
            backgroundColor: 'ffffffff',
            borderColor: openHandsColors.border,
          },
          logo: {
            enabled: true,
            formInclusion: 'IN',
            location: 'CENTER',
            position: 'TOP',
          },
        },
        pageBackground: {
          darkMode: { color: openHandsColors.base },
          lightMode: { color: 'f8fafcff' },
          image: { enabled: false },
        },
      },
    };

    const managedLoginAssets = [
      {
        Bytes: readAssetBase64('assets/cognito-managed-login/openhands-logo-white.svg'),
        Category: 'FORM_LOGO',
        ColorMode: 'DARK',
        Extension: 'SVG',
      },
      {
        Bytes: readAssetBase64('assets/cognito-managed-login/openhands-logo.svg'),
        Category: 'FORM_LOGO',
        ColorMode: 'LIGHT',
        Extension: 'SVG',
      },
      {
        Bytes: readAssetBase64('assets/cognito-managed-login/favicon.svg'),
        Category: 'FAVICON_SVG',
        ColorMode: 'DARK',
        Extension: 'SVG',
      },
      {
        Bytes: readAssetBase64('assets/cognito-managed-login/favicon.svg'),
        Category: 'FAVICON_SVG',
        ColorMode: 'LIGHT',
        Extension: 'SVG',
      },
    ];

    const managedLoginBranding = new cdk.CfnResource(this, 'ManagedLoginBranding', {
      type: 'AWS::Cognito::ManagedLoginBranding',
      properties: {
        UserPoolId: userPool.userPoolId,
        ClientId: userPoolClient.userPoolClientId,
        ReturnMergedResources: false,
        Settings: managedLoginSettings,
        Assets: managedLoginAssets,
        UseCognitoProvidedValues: false,
      },
    });
    managedLoginBranding.node.addDependency(cfnUserPoolDomain);

    // Store the Cognito client secret for Lambda@Edge token exchange.
    // Lambda@Edge retrieves this secret at runtime from Secrets Manager via CloudFormation dynamic reference.
    const clientSecretName =
      props.clientSecretName ?? `openhands/cognito-client-secret-${domainPrefixSuffix}`;
    new secretsmanager.Secret(this, 'CognitoClientSecret', {
      secretName: clientSecretName,
      description: 'Cognito User Pool Client Secret for OpenHands',
      secretStringValue: userPoolClient.userPoolClientSecret,
    });

    this.output = {
      userPoolId: userPool.userPoolId,
      userPoolDomainPrefix: userPoolDomain.domainName,
      userPoolClientId: userPoolClient.userPoolClientId,
      clientSecretName,
      region: this.region,
    };

    new cdk.CfnOutput(this, 'UserPoolId', { value: userPool.userPoolId });
    new cdk.CfnOutput(this, 'UserPoolDomainPrefix', { value: userPoolDomain.domainName });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: userPoolClient.userPoolClientId });
    new cdk.CfnOutput(this, 'ClientSecretName', { value: clientSecretName });
  }
}
