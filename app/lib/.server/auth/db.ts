import { Pool } from 'pg';

export interface AuthUser {
  id: string;
  email: string;
  name: string | null;
  password_hash: string;
  created_at: string;
  updated_at: string;
}

let pool: Pool | null = null;

function getDatabaseUrl(): string {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required');
  }

  return databaseUrl;
}

function getPool(): Pool {
  if (!pool) {
    pool = new Pool({
      connectionString: getDatabaseUrl(),
      max: 10,
    });
  }

  return pool;
}

export async function findUserByEmail(email: string): Promise<AuthUser | null> {
  const result = await getPool().query<AuthUser>(
    'SELECT id, email, name, password_hash, created_at, updated_at FROM app_users WHERE email = $1 LIMIT 1',
    [email.toLowerCase()],
  );

  return result.rows[0] ?? null;
}

export async function findUserById(userId: string): Promise<AuthUser | null> {
  const result = await getPool().query<AuthUser>(
    'SELECT id, email, name, password_hash, created_at, updated_at FROM app_users WHERE id = $1 LIMIT 1',
    [userId],
  );

  return result.rows[0] ?? null;
}

export async function createUser(email: string, passwordHash: string, name?: string): Promise<AuthUser> {
  const result = await getPool().query<AuthUser>(
    `INSERT INTO app_users (email, password_hash, name)
     VALUES ($1, $2, $3)
     RETURNING id, email, name, password_hash, created_at, updated_at`,
    [email.toLowerCase(), passwordHash, name ?? null],
  );

  return result.rows[0];
}
