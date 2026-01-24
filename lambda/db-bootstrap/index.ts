import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { Client } from 'pg';

type RequestType = 'Create' | 'Update' | 'Delete';

type OnEvent = {
  RequestType: RequestType;
  PhysicalResourceId?: string;
  ResourceProperties: Record<string, unknown>;
};

type DbSecret = {
  username: string;
  password: string;
};

const secrets = new SecretsManagerClient({});

function requireString(props: Record<string, unknown>, key: string): string {
  const value = props[key];
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`Missing or invalid property: ${key}`);
  }
  return value;
}

function assertSafeIdentifier(value: string, key: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) {
    throw new Error(`Invalid identifier for ${key}: ${value}`);
  }
}

async function getSecretJson(secretId: string): Promise<DbSecret> {
  const resp = await secrets.send(new GetSecretValueCommand({ SecretId: secretId }));
  if (!resp.SecretString) {
    throw new Error(`SecretString missing for secret: ${secretId}`);
  }
  const parsed = JSON.parse(resp.SecretString) as Partial<DbSecret>;
  if (!parsed.username || !parsed.password) {
    throw new Error(`Secret missing username/password: ${secretId}`);
  }
  return { username: parsed.username, password: parsed.password };
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function connectWithRetries(client: Client, attempts: number, delayMs: number): Promise<void> {
  let lastError: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      await client.connect();
      return;
    } catch (err) {
      lastError = err;
      await sleep(delayMs);
    }
  }
  throw new Error(`Failed to connect to database after ${attempts} attempts: ${String(lastError)}`);
}

async function roleExists(client: Client, roleName: string): Promise<boolean> {
  const result = await client.query('SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1 LIMIT 1', [roleName]);
  return (result.rowCount ?? 0) > 0;
}

async function enumTypeExists(client: Client, schema: string, typeName: string): Promise<boolean> {
  const result = await client.query(
    `
      SELECT 1
      FROM pg_type t
      JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE t.typname = $1
        AND n.nspname = $2
      LIMIT 1
    `.trim(),
    [typeName, schema]
  );
  return (result.rowCount ?? 0) > 0;
}

export async function handler(event: OnEvent) {
  if (event.RequestType === 'Delete') {
    return { PhysicalResourceId: event.PhysicalResourceId ?? 'openhands-db-bootstrap' };
  }

  const props = event.ResourceProperties;
  const adminSecretArn = requireString(props, 'adminSecretArn');
  const proxySecretArn = requireString(props, 'proxySecretArn');
  const host = requireString(props, 'host');
  const portRaw = requireString(props, 'port');
  const database = requireString(props, 'database');
  const iamDatabaseUser = requireString(props, 'iamDatabaseUser');
  const proxyDatabaseUser = requireString(props, 'proxyDatabaseUser');

  assertSafeIdentifier(database, 'database');
  assertSafeIdentifier(iamDatabaseUser, 'iamDatabaseUser');
  assertSafeIdentifier(proxyDatabaseUser, 'proxyDatabaseUser');

  const port = Number.parseInt(portRaw, 10);
  if (!Number.isFinite(port) || port <= 0) {
    throw new Error(`Invalid port: ${portRaw}`);
  }

  const admin = await getSecretJson(adminSecretArn);
  const proxy = await getSecretJson(proxySecretArn);

  const client = new Client({
    host,
    port,
    database,
    user: admin.username,
    password: admin.password,
    ssl: { rejectUnauthorized: true },
  });

  try {
    await connectWithRetries(client, 12, 5000);

    // Ensure roles exist.
    if (!(await roleExists(client, iamDatabaseUser))) {
      await client.query(`CREATE USER "${iamDatabaseUser}"`);
    }
    await client.query(`GRANT rds_iam TO "${iamDatabaseUser}"`);

    if (!(await roleExists(client, proxyDatabaseUser))) {
      await client.query(`CREATE USER "${proxyDatabaseUser}"`);
    }

    // Disable statement logging temporarily to prevent the password from appearing
    // in PostgreSQL logs (the RDS parameter group sets log_statement=ddl by default).
    await client.query("SET log_statement = 'none'");

    // Postgres treats PASSWORD as a string literal in DDL, so we must embed it safely.
    // Validate password contains only printable ASCII characters (no control chars).
    // Secrets Manager typically generates alphanumeric passwords, but we validate defensively.
    if (!/^[\x20-\x7E]+$/.test(proxy.password)) {
      throw new Error('Proxy password contains invalid characters (must be printable ASCII)');
    }
    // Escape backslashes first, then single quotes (PostgreSQL string literal escaping)
    const escapedPassword = proxy.password.replace(/\\/g, '\\\\').replace(/'/g, "''");
    await client.query(`ALTER USER "${proxyDatabaseUser}" WITH PASSWORD '${escapedPassword}'`);

    // Workaround for OpenHands migration expecting this enum type to exist.
    if (!(await enumTypeExists(client, 'public', 'eventcallbackstatus'))) {
      await client.query(
        "CREATE TYPE public.eventcallbackstatus AS ENUM ('ACTIVE', 'DISABLED', 'COMPLETED', 'ERROR')"
      );
    }

    // Grant full database access to both users.
    async function grantUserAccess(userName: string): Promise<void> {
      await client.query(`GRANT ALL PRIVILEGES ON DATABASE "${database}" TO "${userName}"`);
      await client.query(`GRANT ALL ON SCHEMA public TO "${userName}"`);
      await client.query(`GRANT CREATE ON SCHEMA public TO "${userName}"`);
      await client.query(`GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "${userName}"`);
      await client.query(`GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "${userName}"`);
      await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "${userName}"`);
      await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "${userName}"`);
    }

    await grantUserAccess(iamDatabaseUser);
    await grantUserAccess(proxyDatabaseUser);
  } finally {
    await client.end().catch((err) => {
      // Log cleanup errors at debug level (non-fatal but useful for diagnosing connection issues)
      console.log('Connection cleanup warning (non-fatal):', err instanceof Error ? err.message : String(err));
    });
  }

  return { PhysicalResourceId: event.PhysicalResourceId ?? 'openhands-db-bootstrap' };
}
