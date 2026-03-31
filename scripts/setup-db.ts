/**
 * ShieldX Database Migration Runner
 *
 * Reads DATABASE_URL from environment, connects to PostgreSQL,
 * and runs all SQL migration files in order.
 *
 * Usage:
 *   npm run db:migrate            # Run pending migrations
 *   npm run db:migrate -- --reset # Drop all shieldx_* tables, then re-run
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';

const MIGRATIONS_DIR = join(__dirname, '..', 'src', 'learning', 'migrations');

const TABLE_DROP_ORDER = [
  'shieldx_drift_reports',
  'shieldx_conversation_turns',
  'shieldx_conversation_state',
  'shieldx_attack_edges',
  'shieldx_attack_nodes',
  'shieldx_embeddings',
  'shieldx_feedback',
  'shieldx_incidents',
  'shieldx_sessions',
  'shieldx_patterns',
];

function getMigrationFiles(): readonly string[] {
  const files = readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  if (files.length === 0) {
    throw new Error(`No .sql files found in ${MIGRATIONS_DIR}`);
  }

  return files;
}

async function createClient(): Promise<Client> {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error(
      'DATABASE_URL environment variable is required.\n' +
        'Example: DATABASE_URL=postgresql://user:pass@localhost:5432/shieldx',
    );
  }

  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  return client;
}

async function dropAllTables(client: Client): Promise<void> {
  console.log('\n--- RESET MODE: Dropping all shieldx_* tables ---\n');

  for (const table of TABLE_DROP_ORDER) {
    try {
      await client.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
      console.log(`  Dropped: ${table}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.warn(`  Warning dropping ${table}: ${message}`);
    }
  }

  console.log('\n--- All tables dropped ---\n');
}

async function runMigration(
  client: Client,
  filename: string,
): Promise<void> {
  const filepath = join(MIGRATIONS_DIR, filename);
  const sql = readFileSync(filepath, 'utf-8');

  const startMs = performance.now();
  await client.query(sql);
  const durationMs = (performance.now() - startMs).toFixed(1);

  console.log(`  [OK] ${filename} (${durationMs}ms)`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const resetMode = args.includes('--reset');

  console.log('ShieldX Database Migration Runner');
  console.log('=================================\n');

  const migrationFiles = getMigrationFiles();
  console.log(`Found ${migrationFiles.length} migration(s) in ${MIGRATIONS_DIR}\n`);

  const client = await createClient();

  try {
    if (resetMode) {
      await dropAllTables(client);
    }

    console.log('Running migrations:\n');

    for (const file of migrationFiles) {
      await runMigration(client, file);
    }

    console.log('\nAll migrations completed successfully.');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`\nMigration failed: ${message}`);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}

main();
