import sharp from "sharp";

const IMAGE_DATA_URL_REGEX =
  /^data:image\/(png|jpe?g|webp);base64,([A-Za-z0-9+/=\r\n]+)$/i;

const MAX_IMAGE_DIMENSION = Number(process.env.IMAGE_MAX_DIMENSION || 1024);
const IMAGE_QUALITY = Number(process.env.IMAGE_QUALITY || 72);
const IMAGE_MIN_DIMENSION = Number(process.env.IMAGE_MIN_DIMENSION || 320);
const IMAGE_MAX_BYTES = Number(process.env.IMAGE_MAX_BYTES || 450 * 1024);
const COMPRESSION_ATTEMPTS = Number(
  process.env.IMAGE_COMPRESSION_ATTEMPTS || 6,
);

const isObject = (value) =>
  value && typeof value === "object" && !Array.isArray(value);

const clamp = (value, min, max) => Math.min(Math.max(value, min), max);

const getCompressionProfile = (inputBytes) => {
  if (inputBytes > 8 * 1024 * 1024) {
    return { dimension: 700, quality: 48 };
  }

  if (inputBytes > 4 * 1024 * 1024) {
    return { dimension: 850, quality: 56 };
  }

  if (inputBytes > 2 * 1024 * 1024) {
    return { dimension: 960, quality: 62 };
  }

  return {
    dimension: MAX_IMAGE_DIMENSION,
    quality: IMAGE_QUALITY,
  };
};

const compressDataUrlImage = async (input) => {
  const match = IMAGE_DATA_URL_REGEX.exec(input);
  if (!match) {
    return input;
  }

  const base64 = match[2].replace(/\s/g, "");
  const buffer = Buffer.from(base64, "base64");
  const profile = getCompressionProfile(buffer.length);
  const maxAttempts = clamp(COMPRESSION_ATTEMPTS, 1, 10);
  const maxBytes = Math.max(32 * 1024, IMAGE_MAX_BYTES);

  try {
    let bestCompressed = null;

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const qualityStep = attempt * 7;
      const dimensionStep = attempt * 90;
      const widthHeight = Math.max(
        IMAGE_MIN_DIMENSION,
        profile.dimension - dimensionStep,
      );
      const quality = clamp(profile.quality - qualityStep, 35, 90);

      const compressed = await sharp(buffer)
        .rotate()
        .resize({
          width: widthHeight,
          height: widthHeight,
          fit: "inside",
          withoutEnlargement: true,
        })
        .jpeg({ quality, mozjpeg: true })
        .toBuffer();

      if (!bestCompressed || compressed.length < bestCompressed.length) {
        bestCompressed = compressed;
      }

      if (compressed.length <= maxBytes) {
        bestCompressed = compressed;
        break;
      }
    }

    if (!bestCompressed) {
      return input;
    }

    const outputBase64 = bestCompressed.toString("base64");
    return `data:image/jpeg;base64,${outputBase64}`;
  } catch {
    return input;
  }
};

const compressImagesRecursively = async (value) => {
  if (typeof value === "string") {
    return compressDataUrlImage(value);
  }

  if (Array.isArray(value)) {
    const nextArray = [];
    for (const item of value) {
      nextArray.push(await compressImagesRecursively(item));
    }
    return nextArray;
  }

  if (isObject(value)) {
    const nextObject = {};
    for (const [key, childValue] of Object.entries(value)) {
      nextObject[key] = await compressImagesRecursively(childValue);
    }
    return nextObject;
  }

  return value;
};

export const compressCharacterImages = async (character) =>
  compressImagesRecursively(character);
