const REQUIRED_CHARACTER_KEYS = [
  "id",
  "nome",
  "nivel",
  "jogador",
  "xp",
  "conceito",
  "naipe",
  "carga",
  "mov",
  "atributos",
  "combate",
  "pericias",
  "conhecimentos",
  "tecnicasBasicas",
  "vantagens",
  "desvantagens",
  "poderes",
  "equipamentos",
];

export const isValidCharacterPayload = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  return REQUIRED_CHARACTER_KEYS.every((key) => key in value);
};

export const isStrongEnoughPassword = (password) =>
  typeof password === "string" && password.trim().length >= 4;
