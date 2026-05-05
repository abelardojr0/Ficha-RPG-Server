import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import multer from "multer";
import { ensureDatabaseSchema, pool, query } from "./db.js";
import { compressCharacterImages } from "./image.js";
import {
  isStrongEnoughPassword,
  isValidCharacterPayload,
} from "./validation.js";

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 3001);
const requestBodyLimit = process.env.REQUEST_BODY_LIMIT || "12mb";
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

const GROUP_FILE_MIME_WHITELIST = new Set([
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.oasis.opendocument.text",
  "application/rtf",
  "text/plain",
]);

const IMAGE_PROVIDER = (process.env.IMAGE_PROVIDER || "cloudinary")
  .trim()
  .toLowerCase();
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME?.trim() || "";
const CLOUDINARY_URL = process.env.CLOUDINARY_URL?.trim() || "";
const CLOUDINARY_UPLOAD_PRESET =
  process.env.CLOUDINARY_UPLOAD_PRESET?.trim() || "";
const CLOUDINARY_UPLOAD_FOLDER =
  process.env.CLOUDINARY_UPLOAD_FOLDER?.trim() || "";

const normalizeCloudinaryUrl = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  // Accept values copied as "CLOUDINARY_URL=cloudinary://..."
  const withoutPrefix = value.replace(/^\s*CLOUDINARY_URL\s*=\s*/i, "");
  return withoutPrefix.replace(/^['"]|['"]$/g, "").trim();
};

const getUploadFailureMessage = (error, fallbackMessage) => {
  const detail = typeof error?.message === "string" ? error.message.trim() : "";
  if (!detail) {
    return fallbackMessage;
  }

  return `${fallbackMessage} ${detail}`;
};

const getCloudinaryCredentialsFromUrl = () => {
  const normalizedCloudinaryUrl = normalizeCloudinaryUrl(CLOUDINARY_URL);
  if (!normalizedCloudinaryUrl) {
    return null;
  }

  try {
    const parsed = new URL(normalizedCloudinaryUrl);
    const apiKey = decodeURIComponent(parsed.username || "").trim();
    const apiSecret = decodeURIComponent(parsed.password || "").trim();
    const cloudName = decodeURIComponent(parsed.hostname || "").trim();

    if (!apiKey || !apiSecret || !cloudName) {
      return null;
    }

    return { apiKey, apiSecret, cloudName };
  } catch {
    return null;
  }
};

const uploadImageToCloudinary = async (file) => {
  const signedCredentials = getCloudinaryCredentialsFromUrl();
  const resolvedCloudName =
    CLOUDINARY_CLOUD_NAME || signedCredentials?.cloudName || "";
  if (!resolvedCloudName) {
    throw new Error(
      "CLOUDINARY_CLOUD_NAME ou CLOUDINARY_URL sao obrigatorios.",
    );
  }

  const uploadUrl = `https://api.cloudinary.com/v1_1/${resolvedCloudName}/image/upload`;
  const imageBlob = new Blob([file.buffer], {
    type: file.mimetype || "application/octet-stream",
  });
  const formData = new FormData();

  formData.append("file", imageBlob, file.originalname || "image-upload.jpg");

  if (signedCredentials?.apiKey && signedCredentials?.apiSecret) {
    const timestamp = Math.floor(Date.now() / 1000);
    const signingParams = {
      timestamp: String(timestamp),
    };

    if (CLOUDINARY_UPLOAD_FOLDER) {
      signingParams.folder = CLOUDINARY_UPLOAD_FOLDER;
      formData.append("folder", CLOUDINARY_UPLOAD_FOLDER);
    }

    const signatureBase = Object.entries(signingParams)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("&");
    const signature = crypto
      .createHash("sha1")
      .update(`${signatureBase}${signedCredentials.apiSecret}`)
      .digest("hex");

    formData.append("api_key", signedCredentials.apiKey);
    formData.append("timestamp", String(timestamp));
    formData.append("signature", signature);
  } else {
    if (!CLOUDINARY_UPLOAD_PRESET) {
      throw new Error(
        "Defina CLOUDINARY_UPLOAD_PRESET (unsigned) ou CLOUDINARY_URL (signed).",
      );
    }

    formData.append("upload_preset", CLOUDINARY_UPLOAD_PRESET);
    if (CLOUDINARY_UPLOAD_FOLDER) {
      formData.append("folder", CLOUDINARY_UPLOAD_FOLDER);
    }
  }

  const response = await fetch(uploadUrl, {
    method: "POST",
    body: formData,
  });
  const payload = await response.json();

  if (!response.ok) {
    const providerMessage =
      payload?.error?.message || payload?.message || "Falha no upload.";
    throw new Error(`Cloudinary: ${providerMessage}`);
  }

  const imageUrl = payload?.secure_url || payload?.url;
  if (typeof imageUrl !== "string" || !imageUrl.trim()) {
    throw new Error("Cloudinary nao retornou URL da imagem.");
  }

  return imageUrl.trim();
};

const uploadImageToProvider = async (file) => {
  if (!file?.buffer || !Buffer.isBuffer(file.buffer)) {
    throw new Error("Arquivo de imagem invalido.");
  }

  if (IMAGE_PROVIDER === "cloudinary") {
    return uploadImageToCloudinary(file);
  }

  throw new Error(`Provedor de imagem nao suportado: ${IMAGE_PROVIDER}`);
};

const groupFileStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    const safeExtension =
      extension && extension.length <= 6 ? extension : ".bin";
    cb(null, `${Date.now()}-${crypto.randomUUID()}${safeExtension}`);
  },
});

const uploadImage = multer({
  storage: multer.memoryStorage(),
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

const uploadGroupFile = multer({
  storage: groupFileStorage,
  limits: {
    fileSize: 20 * 1024 * 1024,
  },
  fileFilter: (_req, file, cb) => {
    if (!GROUP_FILE_MIME_WHITELIST.has(file.mimetype)) {
      cb(new Error("Formato de arquivo nao suportado."));
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

const getRequestBaseUrl = (req) => {
  const publicBaseUrl = process.env.PUBLIC_BASE_URL?.trim();
  if (publicBaseUrl) {
    return publicBaseUrl.replace(/\/$/, "");
  }

  const forwardedProto = req.headers["x-forwarded-proto"];
  const protocol =
    typeof forwardedProto === "string"
      ? forwardedProto.split(",")[0].trim()
      : req.protocol;
  const host = req.get("host");

  return `${protocol}://${host}`;
};

const buildPublicFileUrl = (req, filename) => {
  return `${getRequestBaseUrl(req)}/uploads/${filename}`;
};

const buildSheetImageUrl = (req, id) => {
  return `${getRequestBaseUrl(req)}/api/sheets/${id}/image`;
};

const buildGroupImageEndpointUrl = (req, id) => {
  return `${getRequestBaseUrl(req)}/api/groups/${id}/image`;
};

const DEFAULT_GROUP_NAME = "Sem grupo";

const normalizeImageValue = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  const normalized = value.trim();
  return normalized;
};

const getSheetImageUrl = (data) => {
  return (
    normalizeImageValue(data?.imagemUrl) ||
    normalizeImageValue(data?.imageUrl) ||
    normalizeImageValue(data?.fotoUrl) ||
    normalizeImageValue(data?.foto) ||
    ""
  );
};

const normalizeGroupName = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim();
};

const getGroupImageSource = (group) => {
  return normalizeImageValue(
    group?.image_url || group?.imagemUrl || group?.imageUrl,
  );
};

const buildGroupImageViewUrl = (req, groupId, group) => {
  const source = getGroupImageSource(group);
  if (!source) {
    return "";
  }

  if (/^https?:\/\//i.test(source)) {
    return source;
  }

  return buildGroupImageEndpointUrl(req, groupId);
};

const buildGroupSummary = ({ req, group }) => {
  const imageUrl = getGroupImageSource(group);
  const imageViewUrl = buildGroupImageViewUrl(req, group.id, group);

  return {
    id: group.id,
    nome: group.nome,
    imagemUrl: imageUrl,
    imagemViewUrl: imageViewUrl,
    imageUrl: imageViewUrl,
    fotoUrl: imageViewUrl,
    sheetCount: Number(group.sheet_count || 0),
    attachmentCount: Number(group.attachment_count || 0),
  };
};

const buildGroupAttachmentSummary = (fileRow) => ({
  id: fileRow.id,
  nome: fileRow.original_name,
  mimeType: fileRow.mime_type,
  tamanhoBytes: Number(fileRow.size_bytes || 0),
  url: fileRow.file_url,
  createdAt: fileRow.created_at,
});

const getSheetGroup = (data, fallbackGroupName = DEFAULT_GROUP_NAME) => {
  return (
    normalizeGroupName(data?.grupo) ||
    normalizeGroupName(fallbackGroupName) ||
    DEFAULT_GROUP_NAME
  );
};

const buildImageViewUrl = ({ req, id, data }) => {
  const rawImageValue = getSheetImageUrl(data);
  if (!rawImageValue) {
    return "";
  }

  if (/^https?:\/\//i.test(rawImageValue)) {
    return rawImageValue;
  }

  return buildSheetImageUrl(req, id);
};

const buildCharacterForResponse = ({ req, id, data, groupName }) => {
  const originalImageUrl = getSheetImageUrl(data);
  const imagemViewUrl = buildImageViewUrl({ req, id, data });
  const grupo = getSheetGroup(data, groupName);

  return {
    ...(data ?? {}),
    grupo,
    imagemUrl: originalImageUrl,
    imagemViewUrl,
    imageUrl: imagemViewUrl,
    fotoUrl: imagemViewUrl,
  };
};

const buildSheetSummary = ({ req, id, data, groupName, updatedAt }) => {
  const originalImageUrl = getSheetImageUrl(data);
  const imagemViewUrl = buildImageViewUrl({ req, id, data });
  const grupo = getSheetGroup(data, groupName);

  return {
    id: String(id),
    nome: data?.nome || "Sem nome",
    grupo,
    nivel: data?.nivel || "",
    jogador: data?.jogador || "",
    imagemUrl: originalImageUrl,
    imagemViewUrl,
    imageUrl: imagemViewUrl,
    fotoUrl: imagemViewUrl,
    updatedAt: updatedAt || new Date().toISOString(),
  };
};

const getOrCreateGroupByName = async (groupName) => {
  const normalizedGroupName =
    normalizeGroupName(groupName) || DEFAULT_GROUP_NAME;
  const nextGroupId = crypto.randomUUID();

  const { rows } = await query(
    `
    WITH existing AS (
      SELECT id, nome
      FROM grupos
      WHERE LOWER(nome) = LOWER($1)
      LIMIT 1
    ),
    inserted AS (
      INSERT INTO grupos (id, nome)
      SELECT $2::uuid, $1
      WHERE NOT EXISTS (SELECT 1 FROM existing)
      RETURNING id, nome
    )
    SELECT id::text AS id, nome FROM inserted
    UNION ALL
    SELECT id::text AS id, nome FROM existing
    LIMIT 1
    `,
    [normalizedGroupName, nextGroupId],
  );

  return rows[0];
};

const listGroupsWithSheetCounts = async () => {
  const { rows } = await query(
    `
    SELECT
      g.id::text AS id,
      g.nome,
      g.image_url,
      COUNT(f.id)::int AS sheet_count,
      (
        SELECT COUNT(*)::int
        FROM grupo_arquivos ga
        WHERE ga.grupo_id = g.id
      ) AS attachment_count
    FROM grupos g
    LEFT JOIN fichas f ON f.grupo_id = g.id
    GROUP BY g.id, g.nome, g.image_url
    ORDER BY LOWER(g.nome) ASC
    `,
  );

  return rows;
};

const listGroupFiles = async (groupId) => {
  const { rows } = await query(
    `
    SELECT
      id::text AS id,
      grupo_id::text AS grupo_id,
      original_name,
      file_url,
      mime_type,
      size_bytes,
      created_at
    FROM grupo_arquivos
    WHERE grupo_id = $1::uuid
    ORDER BY created_at DESC
    `,
    [groupId],
  );

  return rows;
};

const getGroupById = async (id) => {
  const { rows } = await query(
    `
    SELECT g.id::text AS id, g.nome, g.image_url
    FROM grupos g
    WHERE g.id = $1::uuid
    LIMIT 1
    `,
    [id],
  );

  return rows[0] ?? null;
};

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
app.use(express.json({ limit: requestBodyLimit }));
app.use("/uploads", express.static(uploadsDir));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/groups", async (_req, res) => {
  try {
    const groups = await listGroupsWithSheetCounts();

    res.status(200).json({
      groups: groups.map((group) => buildGroupSummary({ req: _req, group })),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Falha ao listar grupos." });
  }
});

app.post("/api/groups", async (req, res) => {
  try {
    const nome = normalizeGroupName(req.body?.nome);
    if (!nome) {
      res.status(400).json({ message: "Nome do grupo obrigatorio." });
      return;
    }

    const group = await getOrCreateGroupByName(nome);
    const groups = await listGroupsWithSheetCounts();
    const groupSummary = groups.find((item) => item.id === group.id);

    res.status(201).json({
      group: buildGroupSummary({ req, group: groupSummary || group }),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Falha ao criar grupo." });
  }
});

app.patch("/api/groups/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const nome = normalizeGroupName(req.body?.nome);

    if (!nome) {
      res.status(400).json({ message: "Nome do grupo obrigatorio." });
      return;
    }

    const existingGroup = await getGroupById(id);
    if (!existingGroup) {
      res.status(404).json({ message: "Grupo nao encontrado." });
      return;
    }

    try {
      await query(`UPDATE grupos SET nome = $2 WHERE id = $1::uuid`, [
        id,
        nome,
      ]);
    } catch (dbError) {
      if (dbError?.code === "23505") {
        res.status(409).json({ message: "Ja existe um grupo com esse nome." });
        return;
      }

      throw dbError;
    }

    await query(
      `
      UPDATE fichas
      SET data = jsonb_set(data, '{grupo}', to_jsonb($2::text), true)
      WHERE grupo_id = $1::uuid
      `,
      [id, nome],
    );

    const groups = await listGroupsWithSheetCounts();
    const group = groups.find((item) => item.id === id);

    res.status(200).json({
      group: buildGroupSummary({ req, group: group || { id, nome } }),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Falha ao renomear grupo." });
  }
});

app.get("/api/groups/:id/image", async (req, res) => {
  try {
    const { id } = req.params;
    const group = await getGroupById(id);

    if (!group) {
      res.status(404).json({ message: "Grupo nao encontrado." });
      return;
    }

    const imageSource = getGroupImageSource(group);
    if (!imageSource) {
      res.status(404).json({ message: "Imagem do grupo nao encontrada." });
      return;
    }

    if (/^data:image\/[a-zA-Z0-9.+-]+;base64,/.test(imageSource)) {
      const [metadata, base64Payload] = imageSource.split(",", 2);
      const mimeMatch = /^data:(image\/[a-zA-Z0-9.+-]+);base64$/.exec(metadata);

      if (!mimeMatch || !base64Payload) {
        res.status(400).json({ message: "Formato de imagem invalido." });
        return;
      }

      const imageBuffer = Buffer.from(base64Payload, "base64");
      res.setHeader("Content-Type", mimeMatch[1]);
      res.setHeader("Cache-Control", "public, max-age=300");
      res.send(imageBuffer);
      return;
    }

    const localFilename = getLocalUploadFilenameFromUrl(imageSource);
    if (localFilename) {
      const filePath = path.resolve(uploadsDir, localFilename);
      if (!filePath.startsWith(uploadsDir)) {
        res.status(400).json({ message: "Caminho de imagem invalido." });
        return;
      }

      if (!fs.existsSync(filePath)) {
        res.status(404).json({ message: "Arquivo de imagem nao encontrado." });
        return;
      }

      res.sendFile(filePath);
      return;
    }

    if (/^https?:\/\//i.test(imageSource)) {
      res.redirect(302, imageSource);
      return;
    }

    res.status(400).json({ message: "Referencia de imagem invalida." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Falha ao carregar imagem do grupo." });
  }
});

app.post("/api/groups/:id/image", (req, res) => {
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
      const group = await getGroupById(id);

      if (!group) {
        res.status(404).json({ message: "Grupo nao encontrado." });
        return;
      }

      if (!req.file) {
        res.status(400).json({ message: "Arquivo de imagem obrigatorio." });
        return;
      }

      const previousImageUrl = getGroupImageSource(group);
      const nextImageUrl = await uploadImageToProvider(req.file);

      await query(`UPDATE grupos SET image_url = $2 WHERE id = $1::uuid`, [
        id,
        nextImageUrl,
      ]);

      if (previousImageUrl && previousImageUrl !== nextImageUrl) {
        deleteLocalUploadByUrl(previousImageUrl);
      }

      const updatedGroup = await getGroupById(id);

      res.status(201).json({
        group: buildGroupSummary({ req, group: updatedGroup }),
      });
    };

    processUpload().catch((uploadProcessError) => {
      console.error(uploadProcessError);
      res.status(500).json({
        message: getUploadFailureMessage(
          uploadProcessError,
          "Falha ao salvar imagem do grupo.",
        ),
      });
    });
  });
});

app.delete("/api/groups/:id/image", async (req, res) => {
  try {
    const { id } = req.params;
    const group = await getGroupById(id);

    if (!group) {
      res.status(404).json({ message: "Grupo nao encontrado." });
      return;
    }

    const currentImageUrl = getGroupImageSource(group);

    await query(`UPDATE grupos SET image_url = '' WHERE id = $1::uuid`, [id]);

    if (currentImageUrl) {
      deleteLocalUploadByUrl(currentImageUrl);
    }

    res.status(200).json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Falha ao remover imagem do grupo." });
  }
});

app.get("/api/groups/:id/files", async (req, res) => {
  try {
    const { id } = req.params;
    const group = await getGroupById(id);
    if (!group) {
      res.status(404).json({ message: "Grupo nao encontrado." });
      return;
    }

    const files = await listGroupFiles(id);

    res.status(200).json({
      files: files.map((fileRow) => buildGroupAttachmentSummary(fileRow)),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Falha ao listar arquivos do grupo." });
  }
});

app.post("/api/groups/:id/files", (req, res) => {
  uploadGroupFile.single("file")(req, res, (error) => {
    if (error) {
      if (
        error instanceof multer.MulterError &&
        error.code === "LIMIT_FILE_SIZE"
      ) {
        res
          .status(400)
          .json({ message: "Arquivo muito grande. Limite: 20MB." });
        return;
      }

      res
        .status(400)
        .json({ message: error.message || "Falha no upload do arquivo." });
      return;
    }

    const processUpload = async () => {
      const { id } = req.params;
      const group = await getGroupById(id);
      if (!group) {
        if (req.file?.path) {
          fs.rm(req.file.path, { force: true }, () => {});
        }
        res.status(404).json({ message: "Grupo nao encontrado." });
        return;
      }

      if (!req.file) {
        res.status(400).json({ message: "Arquivo obrigatorio." });
        return;
      }

      const fileId = crypto.randomUUID();
      const fileUrl = buildPublicFileUrl(req, req.file.filename);

      await query(
        `
        INSERT INTO grupo_arquivos (id, grupo_id, original_name, file_url, mime_type, size_bytes)
        VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
        `,
        [
          fileId,
          id,
          req.file.originalname || req.file.filename,
          fileUrl,
          req.file.mimetype || "application/octet-stream",
          req.file.size || 0,
        ],
      );

      const files = await listGroupFiles(id);
      const uploaded = files.find((item) => item.id === fileId);

      res.status(201).json({
        file: buildGroupAttachmentSummary(uploaded || files[0]),
      });
    };

    processUpload().catch((uploadProcessError) => {
      console.error(uploadProcessError);
      if (req.file?.path) {
        fs.rm(req.file.path, { force: true }, () => {});
      }
      res.status(500).json({ message: "Falha ao salvar arquivo do grupo." });
    });
  });
});

app.delete("/api/groups/:id/files/:fileId", async (req, res) => {
  try {
    const { id, fileId } = req.params;
    const group = await getGroupById(id);
    if (!group) {
      res.status(404).json({ message: "Grupo nao encontrado." });
      return;
    }

    const { rows } = await query(
      `
      SELECT id::text AS id, file_url
      FROM grupo_arquivos
      WHERE id = $1::uuid AND grupo_id = $2::uuid
      LIMIT 1
      `,
      [fileId, id],
    );

    const groupFile = rows[0];
    if (!groupFile) {
      res.status(404).json({ message: "Arquivo do grupo nao encontrado." });
      return;
    }

    await query(`DELETE FROM grupo_arquivos WHERE id = $1::uuid`, [fileId]);
    deleteLocalUploadByUrl(groupFile.file_url);

    res.status(200).json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Falha ao remover arquivo do grupo." });
  }
});

app.delete("/api/groups/:id", async (req, res) => {
  const client = await pool.connect();

  try {
    const { id } = req.params;
    const sourceGroup = await getGroupById(id);

    if (!sourceGroup) {
      res.status(404).json({ message: "Grupo nao encontrado." });
      return;
    }

    if (sourceGroup.nome.toLowerCase() === DEFAULT_GROUP_NAME.toLowerCase()) {
      res
        .status(400)
        .json({ message: "O grupo padrao nao pode ser removido." });
      return;
    }

    const moveToGroupId =
      typeof req.body?.moveToGroupId === "string"
        ? req.body.moveToGroupId.trim()
        : "";
    const moveToGroupName = normalizeGroupName(req.body?.moveToGroupName);

    const sheetCountResult = await query(
      `SELECT COUNT(*)::int AS count FROM fichas WHERE grupo_id = $1::uuid`,
      [id],
    );
    const sheetCount = Number(sheetCountResult.rows[0]?.count || 0);

    let destinationGroup = null;

    if (moveToGroupId) {
      if (moveToGroupId === id) {
        res.status(400).json({
          message: "Grupo de destino deve ser diferente do grupo atual.",
        });
        return;
      }

      destinationGroup = await getGroupById(moveToGroupId);
      if (!destinationGroup) {
        res.status(404).json({ message: "Grupo de destino nao encontrado." });
        return;
      }
    } else if (moveToGroupName) {
      destinationGroup = await getOrCreateGroupByName(moveToGroupName);
      if (destinationGroup.id === id) {
        res.status(400).json({
          message: "Grupo de destino deve ser diferente do grupo atual.",
        });
        return;
      }
    }

    if (sheetCount > 0 && !destinationGroup) {
      res.status(409).json({
        message:
          "Grupo possui fichas vinculadas. Informe moveToGroupId ou moveToGroupName para mover antes de excluir.",
        sheetCount,
      });
      return;
    }

    const groupFiles = await listGroupFiles(id);
    const groupFileUrls = groupFiles
      .map((item) => item.file_url)
      .filter(Boolean);
    const currentGroupImageUrl = getGroupImageSource(sourceGroup);

    await client.query("BEGIN");

    if (destinationGroup) {
      await client.query(
        `
        UPDATE fichas
        SET
          grupo_id = $2::uuid,
          data = jsonb_set(data, '{grupo}', to_jsonb($3::text), true)
        WHERE grupo_id = $1::uuid
        `,
        [id, destinationGroup.id, destinationGroup.nome],
      );
    }

    await client.query(`DELETE FROM grupos WHERE id = $1::uuid`, [id]);

    await client.query("COMMIT");

    if (currentGroupImageUrl) {
      deleteLocalUploadByUrl(currentGroupImageUrl);
    }

    for (const fileUrl of groupFileUrls) {
      deleteLocalUploadByUrl(fileUrl);
    }

    res.status(200).json({
      ok: true,
      deletedGroupId: id,
      movedSheetsToGroupId: destinationGroup?.id || null,
      movedSheetsToGroupName: destinationGroup?.nome || null,
      movedSheetCount: destinationGroup ? sheetCount : 0,
    });
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // no-op
    }
    console.error(error);
    res.status(500).json({ message: "Falha ao excluir grupo." });
  } finally {
    client.release();
  }
});

app.get("/api/sheets/:id/image", async (req, res) => {
  try {
    const { id } = req.params;
    const sheet = await getSheetById(id);

    if (!sheet) {
      res.status(404).json({ message: "Ficha nao encontrada." });
      return;
    }

    const imageSource = getSheetImageUrl(sheet.data);
    if (!imageSource) {
      res.status(404).json({ message: "Imagem nao encontrada." });
      return;
    }

    if (/^data:image\/[a-zA-Z0-9.+-]+;base64,/.test(imageSource)) {
      const [metadata, base64Payload] = imageSource.split(",", 2);
      const mimeMatch = /^data:(image\/[a-zA-Z0-9.+-]+);base64$/.exec(metadata);

      if (!mimeMatch || !base64Payload) {
        res.status(400).json({ message: "Formato de imagem invalido." });
        return;
      }

      const imageBuffer = Buffer.from(base64Payload, "base64");
      res.setHeader("Content-Type", mimeMatch[1]);
      res.setHeader("Cache-Control", "public, max-age=300");
      res.send(imageBuffer);
      return;
    }

    const localFilename = getLocalUploadFilenameFromUrl(imageSource);
    if (localFilename) {
      const filePath = path.resolve(uploadsDir, localFilename);
      if (!filePath.startsWith(uploadsDir)) {
        res.status(400).json({ message: "Caminho de imagem invalido." });
        return;
      }

      if (!fs.existsSync(filePath)) {
        res.status(404).json({ message: "Arquivo de imagem nao encontrado." });
        return;
      }

      res.sendFile(filePath);
      return;
    }

    if (/^https?:\/\//i.test(imageSource)) {
      res.redirect(302, imageSource);
      return;
    }

    res.status(400).json({ message: "Referencia de imagem invalida." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Falha ao carregar imagem da ficha." });
  }
});

app.delete("/api/sheets/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body ?? {};

    const auth = await assertSheetAuth(id, password);
    if (!auth.ok) {
      return res.status(auth.status).json({ message: auth.message });
    }

    const imageUrl = getSheetImageUrl(auth.sheet.data);

    await query(`DELETE FROM fichas WHERE id = $1::uuid`, [id]);

    if (imageUrl) {
      deleteLocalUploadByUrl(imageUrl);
    }

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Falha ao excluir ficha." });
  }
});

const getSheetById = async (id) => {
  const { rows } = await query(
    `
    SELECT
      f.id::text AS id,
      f.data,
      f.password_hash,
      f.grupo_id::text AS group_id,
      g.nome AS group_name
    FROM fichas f
    JOIN grupos g ON g.id = f.grupo_id
    WHERE f.id = $1::uuid
    LIMIT 1
    `,
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
        res.status(auth.status).json({ message: auth.message });
        return;
      }

      if (!req.file) {
        res.status(400).json({ message: "Arquivo de imagem obrigatorio." });
        return;
      }

      const previousImageUrl = getSheetImageUrl(auth.sheet.data);
      const nextImageUrl = await uploadImageToProvider(req.file);
      const nextData = {
        ...(auth.sheet.data ?? {}),
        imagemUrl: nextImageUrl,
        imageUrl: nextImageUrl,
        fotoUrl: nextImageUrl,
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
      res.status(500).json({
        message: getUploadFailureMessage(
          uploadProcessError,
          "Falha ao salvar imagem da ficha.",
        ),
      });
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

    const currentImageUrl = getSheetImageUrl(auth.sheet.data);

    const nextData = { ...(auth.sheet.data ?? {}) };
    delete nextData.imagemUrl;
    delete nextData.imageUrl;
    delete nextData.fotoUrl;
    delete nextData.foto;

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
        f.id::text AS id,
        f.data,
        f.updated_at,
        g.nome AS group_name
      FROM fichas f
      JOIN grupos g ON g.id = f.grupo_id
      ORDER BY f.updated_at DESC
      `,
    );

    const sheets = rows.map((row) =>
      buildSheetSummary({
        req: _req,
        id: row.id,
        data: row.data,
        groupName: row.group_name,
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

    const compressedCharacter = await compressCharacterImages(character);
    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 12);
    const group = await getOrCreateGroupByName(
      getSheetGroup(compressedCharacter),
    );
    const characterWithId = {
      ...compressedCharacter,
      id,
      grupo: group.nome,
    };

    await query(
      `
      INSERT INTO fichas (id, data, password_hash, grupo_id)
      VALUES ($1::uuid, $2::jsonb, $3, $4::uuid)
      `,
      [id, JSON.stringify(characterWithId), passwordHash, group.id],
    );

    const summary = buildSheetSummary({
      req,
      id,
      data: characterWithId,
      groupName: group.nome,
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
      character: buildCharacterForResponse({
        req,
        id: sheet.id,
        data: sheet.data,
        groupName: sheet.group_name,
      }),
      summary: buildSheetSummary({
        req,
        id: sheet.id,
        data: sheet.data,
        groupName: sheet.group_name,
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

    const compressedCharacter = await compressCharacterImages(character);
    const group = await getOrCreateGroupByName(
      getSheetGroup(compressedCharacter, auth.sheet.group_name),
    );
    const previousImageUrl = getSheetImageUrl(auth.sheet.data);
    const nextImageUrlFromPayload = getSheetImageUrl(compressedCharacter);
    const nextImageUrl = nextImageUrlFromPayload || previousImageUrl;
    const characterWithId = {
      ...compressedCharacter,
      id,
      grupo: group.nome,
      imagemUrl: nextImageUrl,
      imageUrl: nextImageUrl,
      fotoUrl: nextImageUrl,
    };

    await query(
      `UPDATE fichas SET data = $2::jsonb, grupo_id = $3::uuid WHERE id = $1::uuid`,
      [id, JSON.stringify(characterWithId), group.id],
    );

    if (previousImageUrl && previousImageUrl !== nextImageUrl) {
      deleteLocalUploadByUrl(previousImageUrl);
    }

    return res.json({
      summary: buildSheetSummary({
        req,
        id,
        data: characterWithId,
        groupName: group.nome,
      }),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Falha ao salvar ficha." });
  }
});

app.patch("/api/sheets/:id/group", async (req, res) => {
  try {
    const { id } = req.params;
    const { password, grupo } = req.body ?? {};

    const destinationGroupName = normalizeGroupName(grupo);
    if (!destinationGroupName) {
      res.status(400).json({ message: "Grupo de destino obrigatorio." });
      return;
    }

    const auth = await assertSheetAuth(id, password);
    if (!auth.ok) {
      return res.status(auth.status).json({ message: auth.message });
    }

    const destinationGroup = await getOrCreateGroupByName(destinationGroupName);

    const nextData = {
      ...(auth.sheet.data ?? {}),
      grupo: destinationGroup.nome,
    };

    await query(
      `UPDATE fichas SET data = $2::jsonb, grupo_id = $3::uuid WHERE id = $1::uuid`,
      [id, JSON.stringify(nextData), destinationGroup.id],
    );

    return res.status(200).json({
      summary: buildSheetSummary({
        req,
        id,
        data: nextData,
        groupName: destinationGroup.nome,
      }),
      moved: auth.sheet.group_id !== destinationGroup.id,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Falha ao mover ficha de grupo." });
  }
});

const startServer = async () => {
  await ensureDatabaseSchema();

  app.listen(port, () => {
    console.log(`Servidor backend ativo na porta ${port}`);
  });
};

startServer().catch((error) => {
  console.error("Falha ao inicializar servidor:", error);
  process.exit(1);
});

app.use((error, _req, res, next) => {
  if (error?.type === "entity.too.large") {
    res.status(413).json({
      message:
        "Payload muito grande. Tente enviar uma imagem menor ou comprima antes do envio.",
    });
    return;
  }

  next(error);
});
