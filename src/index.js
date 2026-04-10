import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import { query } from "./db.js";
import {
  isStrongEnoughPassword,
  isValidCharacterPayload,
} from "./validation.js";

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 3001);
const corsOrigin = process.env.CORS_ORIGIN || "http://localhost:5173";

app.use(cors({ origin: corsOrigin }));
app.use(express.json({ limit: "2mb" }));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/sheets", async (_req, res) => {
  try {
    const { rows } = await query(
      `
      SELECT
        id::text AS id,
        COALESCE(data->>'nome', 'Sem nome') AS nome,
        COALESCE(data->>'nivel', '') AS nivel,
        COALESCE(data->>'jogador', '') AS jogador,
        updated_at
      FROM fichas
      ORDER BY updated_at DESC
      `,
    );

    const sheets = rows.map((row) => ({
      id: row.id,
      nome: row.nome,
      nivel: row.nivel,
      jogador: row.jogador,
      updatedAt: row.updated_at,
    }));

    res.json({ sheets });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Falha ao listar fichas." });
  }
});

app.post("/api/sheets", async (req, res) => {
  try {
    const { password, character } = req.body ?? {};

    if (!isStrongEnoughPassword(password)) {
      return res
        .status(400)
        .json({ message: "Senha invalida (minimo 4 caracteres)." });
    }

    if (!isValidCharacterPayload(character)) {
      return res.status(400).json({ message: "Payload da ficha invalido." });
    }

    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 12);
    const characterWithId = { ...character, id };

    await query(
      `INSERT INTO fichas (id, data, password_hash) VALUES ($1::uuid, $2::jsonb, $3)`,
      [id, JSON.stringify(characterWithId), passwordHash],
    );

    const summary = {
      id,
      nome: characterWithId.nome || "Sem nome",
      nivel: characterWithId.nivel || "",
      jogador: characterWithId.jogador || "",
      updatedAt: new Date().toISOString(),
    };

    return res.status(201).json({ id, summary });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Falha ao criar ficha." });
  }
});

app.post("/api/sheets/:id/unlock", async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body ?? {};

    if (typeof password !== "string" || password.length === 0) {
      return res.status(400).json({ message: "Senha obrigatoria." });
    }

    const { rows } = await query(
      `SELECT id::text AS id, data, password_hash FROM fichas WHERE id = $1::uuid LIMIT 1`,
      [id],
    );

    const sheet = rows[0];
    if (!sheet) {
      return res.status(404).json({ message: "Ficha nao encontrada." });
    }

    const validPassword = await bcrypt.compare(password, sheet.password_hash);
    if (!validPassword) {
      return res.status(401).json({ message: "Senha incorreta." });
    }

    return res.json({
      character: sheet.data,
      summary: {
        id: sheet.id,
        nome: sheet.data?.nome || "Sem nome",
        nivel: sheet.data?.nivel || "",
        jogador: sheet.data?.jogador || "",
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Falha ao abrir ficha." });
  }
});

app.put("/api/sheets/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { password, character } = req.body ?? {};

    if (typeof password !== "string" || password.length === 0) {
      return res.status(400).json({ message: "Senha obrigatoria." });
    }

    if (!isValidCharacterPayload(character)) {
      return res.status(400).json({ message: "Payload da ficha invalido." });
    }

    const { rows } = await query(
      `SELECT password_hash FROM fichas WHERE id = $1::uuid LIMIT 1`,
      [id],
    );

    const sheet = rows[0];
    if (!sheet) {
      return res.status(404).json({ message: "Ficha nao encontrada." });
    }

    const validPassword = await bcrypt.compare(password, sheet.password_hash);
    if (!validPassword) {
      return res.status(401).json({ message: "Senha incorreta." });
    }

    const characterWithId = { ...character, id };

    await query(`UPDATE fichas SET data = $2::jsonb WHERE id = $1::uuid`, [
      id,
      JSON.stringify(characterWithId),
    ]);

    return res.json({
      summary: {
        id,
        nome: characterWithId.nome || "Sem nome",
        nivel: characterWithId.nivel || "",
        jogador: characterWithId.jogador || "",
        updatedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Falha ao salvar ficha." });
  }
});

app.listen(port, () => {
  console.log(`Servidor backend ativo na porta ${port}`);
});
