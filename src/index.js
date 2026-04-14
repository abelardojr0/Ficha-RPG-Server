import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import multer from "multer";
import { query } from "./db.js";
import {
  isStrongEnoughPassword,
  isValidCharacterPayload,
} from "./validation.js";

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 3001);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadsDir = path.resolve(__dirname, "../uploads");

fs.mkdirSync(uploadsDir, { recursive: true });

const IMAGE_MIME_WHITELIST = new Set([
  "image/png",
  "image/jpeg",
  "image/jpg",
  "image/webp",
  "image/gif",
]);

const uploadStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    const safeExtension =
      extension && extension.length <= 6 ? extension : ".bin";
    cb(null, `${Date.now()}-${crypto.randomUUID()}${safeExtension}`);
  },
});

const uploadImage = multer({
  storage: uploadStorage,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (_req, file, cb) => {
    if (!IMAGE_MIME_WHITELIST.has(file.mimetype)) {
      cb(new Error("Formato de imagem nao suportado."));
      return;
    }

    cb(null, true);
  },
});

const LOCAL_UPLOADS_ROUTE_PREFIX = "/uploads/";

const getLocalUploadFilenameFromUrl = (urlValue) => {
  if (typeof urlValue !== "string" || !urlValue.trim()) {
    return null;
  }

  try {
    const parsedUrl = new URL(urlValue);
    const pathname = parsedUrl.pathname || "";
    const markerIndex = pathname.indexOf(LOCAL_UPLOADS_ROUTE_PREFIX);
    if (markerIndex === -1) {
      return null;
    }

    const filename = pathname.slice(
      markerIndex + LOCAL_UPLOADS_ROUTE_PREFIX.length,
    );
    return filename ? path.basename(filename) : null;
  } catch {
    const markerIndex = urlValue.indexOf(LOCAL_UPLOADS_ROUTE_PREFIX);
    if (markerIndex === -1) {
      return null;
    }

    const filename = urlValue.slice(
      markerIndex + LOCAL_UPLOADS_ROUTE_PREFIX.length,
    );
    return filename ? path.basename(filename) : null;
  }
};

const deleteLocalUploadByUrl = (urlValue) => {
  const filename = getLocalUploadFilenameFromUrl(urlValue);
  if (!filename) {
    return;
  }

  const filePath = path.resolve(uploadsDir, filename);
  if (!filePath.startsWith(uploadsDir)) {
    return;
  }

  fs.rm(filePath, { force: true }, () => {});
};

const buildPublicFileUrl = (req, filename) => {
  const publicBaseUrl = process.env.PUBLIC_BASE_URL?.trim();
  if (publicBaseUrl) {
    return `${publicBaseUrl.replace(/\/$/, "")}/uploads/${filename}`;
  }

  const forwardedProto = req.headers["x-forwarded-proto"];
  const protocol =
    typeof forwardedProto === "string"
      ? forwardedProto.split(",")[0].trim()
      : req.protocol;
  const host = req.get("host");

  return `${protocol}://${host}/uploads/${filename}`;
};

const buildSheetSummary = ({ id, data, updatedAt }) => ({
  id: String(id),
  nome: data?.nome || "Sem nome",
  nivel: data?.nivel || "",
  jogador: data?.jogador || "",
  imagemUrl: data?.imagemUrl || data?.imageUrl || "",
  updatedAt: updatedAt || new Date().toISOString(),
});

const corsOriginValue = process.env.CORS_ORIGIN?.trim() || "*";
const allowedOrigins =
  corsOriginValue === "*"
    ? "*"
    : corsOriginValue
        .split(",")
        .map((origin) => origin.trim())
        .filter(Boolean);

const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins === "*" || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }

    callback(new Error("Origem nao permitida pelo CORS."));
  },
};

app.set("trust proxy", true);
app.use(cors(corsOptions));
app.use(express.json({ limit: "2mb" }));
app.use("/uploads", express.static(uploadsDir));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

const getSheetById = async (id) => {
  const { rows } = await query(
    `SELECT id::text AS id, data, password_hash FROM fichas WHERE id = $1::uuid LIMIT 1`,
    [id],
  );

  return rows[0] ?? null;
};

const assertSheetAuth = async (id, password) => {
  if (typeof password !== "string" || password.length === 0) {
    return { ok: false, status: 400, message: "Senha obrigatoria." };
  }

  const sheet = await getSheetById(id);
  if (!sheet) {
    return { ok: false, status: 404, message: "Ficha nao encontrada." };
  }

  const validPassword = await bcrypt.compare(password, sheet.password_hash);
  if (!validPassword) {
    return { ok: false, status: 401, message: "Senha incorreta." };
  }

  return { ok: true, sheet };
};

app.post("/api/sheets/:id/image", (req, res) => {
  uploadImage.single("image")(req, res, (error) => {
    if (error) {
      if (
        error instanceof multer.MulterError &&
        error.code === "LIMIT_FILE_SIZE"
      ) {
        res.status(400).json({ message: "Imagem muito grande. Limite: 5MB." });
        return;
      }

      res
        .status(400)
        .json({ message: error.message || "Falha no upload da imagem." });
      return;
    }

    const processUpload = async () => {
      const { id } = req.params;
      const { password } = req.body ?? {};

      const auth = await assertSheetAuth(id, password);
      if (!auth.ok) {
        if (req.file?.path) {
          fs.rm(req.file.path, { force: true }, () => {});
        }
        res.status(auth.status).json({ message: auth.message });
        return;
      }

      if (!req.file) {
        res.status(400).json({ message: "Arquivo de imagem obrigatorio." });
        return;
      }

      const previousImageUrl = auth.sheet.data?.imagemUrl || "";
      const nextImageUrl = buildPublicFileUrl(req, req.file.filename);
      const nextData = {
        ...(auth.sheet.data ?? {}),
        imagemUrl: nextImageUrl,
      };

      await query(`UPDATE fichas SET data = $2::jsonb WHERE id = $1::uuid`, [
        id,
        JSON.stringify(nextData),
      ]);

      if (previousImageUrl && previousImageUrl !== nextImageUrl) {
        deleteLocalUploadByUrl(previousImageUrl);
      }

      res.status(201).json({ url: nextImageUrl });
    };

    processUpload().catch((uploadProcessError) => {
      console.error(uploadProcessError);
      if (req.file?.path) {
        fs.rm(req.file.path, { force: true }, () => {});
      }
      res.status(500).json({ message: "Falha ao salvar imagem da ficha." });
    });
  });
});

app.delete("/api/sheets/:id/image", async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body ?? {};

    const auth = await assertSheetAuth(id, password);
    if (!auth.ok) {
      res.status(auth.status).json({ message: auth.message });
      return;
    }

    const currentImageUrl = auth.sheet.data?.imagemUrl || "";

    const nextData = { ...(auth.sheet.data ?? {}) };
    delete nextData.imagemUrl;

    await query(`UPDATE fichas SET data = $2::jsonb WHERE id = $1::uuid`, [
      id,
      JSON.stringify(nextData),
    ]);

    if (currentImageUrl) {
      deleteLocalUploadByUrl(currentImageUrl);
    }

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Falha ao remover imagem da ficha." });
  }
});

app.get("/api/sheets", async (_req, res) => {
  try {
    const { rows } = await query(
      `
      SELECT
        id::text AS id,
        data,
        updated_at
      FROM fichas
      ORDER BY updated_at DESC
      `,
    );

    const sheets = rows.map((row) =>
      buildSheetSummary({
        id: row.id,
        data: row.data,
        updatedAt: row.updated_at,
      }),
    );

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

    const summary = buildSheetSummary({
      id,
      data: characterWithId,
    });

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

    const auth = await assertSheetAuth(id, password);
    if (!auth.ok) {
      return res.status(auth.status).json({ message: auth.message });
    }

    const sheet = auth.sheet;

    return res.json({
      character: sheet.data,
      summary: buildSheetSummary({
        id: sheet.id,
        data: sheet.data,
      }),
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

    if (!isValidCharacterPayload(character)) {
      return res.status(400).json({ message: "Payload da ficha invalido." });
    }

    const auth = await assertSheetAuth(id, password);
    if (!auth.ok) {
      return res.status(auth.status).json({ message: auth.message });
    }

    const characterWithId = { ...character, id };
    const previousImageUrl = auth.sheet.data?.imagemUrl || "";
    const nextImageUrl = characterWithId.imagemUrl || "";

    await query(`UPDATE fichas SET data = $2::jsonb WHERE id = $1::uuid`, [
      id,
      JSON.stringify(characterWithId),
    ]);

    if (previousImageUrl && previousImageUrl !== nextImageUrl) {
      deleteLocalUploadByUrl(previousImageUrl);
    }

    return res.json({
      summary: buildSheetSummary({
        id,
        data: characterWithId,
      }),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Falha ao salvar ficha." });
  }
});

app.listen(port, () => {
  console.log(`Servidor backend ativo na porta ${port}`);
});
