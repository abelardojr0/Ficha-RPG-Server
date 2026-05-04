import dotenv from "dotenv";
import pg from "pg";

dotenv.config();

const { Pool } = pg;

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error("DATABASE_URL nao configurada no arquivo .env");
}

const useSsl =
  !connectionString.includes("localhost") &&
  !connectionString.includes("127.0.0.1");

export const pool = new Pool({
  connectionString,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
});

export const query = (text, params) => pool.query(text, params);

const DEFAULT_GROUP_NAME = "Sem grupo";

export const ensureDatabaseSchema = async () => {
  await query(`
    CREATE TABLE IF NOT EXISTS grupos (
      id UUID PRIMARY KEY,
      nome TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  await query(`
    CREATE UNIQUE INDEX IF NOT EXISTS grupos_nome_lower_unique_idx
    ON grupos (LOWER(nome))
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS fichas (
      id UUID PRIMARY KEY,
      data JSONB NOT NULL,
      password_hash TEXT NOT NULL,
      grupo_id UUID,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  await query(`ALTER TABLE fichas ADD COLUMN IF NOT EXISTS grupo_id UUID`);

  await query(
    `
    INSERT INTO grupos (id, nome)
    SELECT $2::uuid, $1
    WHERE NOT EXISTS (
      SELECT 1
      FROM grupos
      WHERE LOWER(nome) = LOWER($1)
    )
    `,
    [DEFAULT_GROUP_NAME, "00000000-0000-0000-0000-000000000001"],
  );

  await query(
    `
    UPDATE fichas
    SET grupo_id = (
      SELECT id
      FROM grupos
      WHERE LOWER(nome) = LOWER($1)
      LIMIT 1
    )
    WHERE grupo_id IS NULL
    `,
    [DEFAULT_GROUP_NAME],
  );

  await query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fichas_grupo_id_fkey'
      ) THEN
        ALTER TABLE fichas
          ADD CONSTRAINT fichas_grupo_id_fkey
          FOREIGN KEY (grupo_id)
          REFERENCES grupos(id)
          ON UPDATE CASCADE
          ON DELETE RESTRICT;
      END IF;
    END
    $$
  `);

  await query(`ALTER TABLE fichas ALTER COLUMN grupo_id SET NOT NULL`);
};
