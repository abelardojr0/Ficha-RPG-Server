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
