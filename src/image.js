import sharp from "sharp";

const IMAGE_DATA_URL_REGEX =
  /^data:image\/(png|jpe?g|webp);base64,([A-Za-z0-9+/=\r\n]+)$/i;

const MAX_IMAGE_DIMENSION = Number(process.env.IMAGE_MAX_DIMENSION || 1024);
const IMAGE_QUALITY = Number(process.env.IMAGE_QUALITY || 72);

const isObject = (value) =>
  value && typeof value === "object" && !Array.isArray(value);

const clamp = (value, min, max) => Math.min(Math.max(value, min), max);

const compressDataUrlImage = async (input) => {
  const match = IMAGE_DATA_URL_REGEX.exec(input);
  if (!match) {
    return input;
  }

  const base64 = match[2].replace(/\s/g, "");
  const buffer = Buffer.from(base64, "base64");

  try {
    const compressed = await sharp(buffer)
      .rotate()
      .resize({
        width: MAX_IMAGE_DIMENSION,
        height: MAX_IMAGE_DIMENSION,
        fit: "inside",
        withoutEnlargement: true,
      })
      .jpeg({ quality: clamp(IMAGE_QUALITY, 40, 90), mozjpeg: true })
      .toBuffer();

    const outputBase64 = compressed.toString("base64");
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
