import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const landingDir = __dirname;
const landingAssetsDir = path.join(landingDir, "assets");

const PORT = Number(process.env.PORT) || 3000;
const CRM_API_KEY = String(process.env.CRM_API_KEY || "").trim();
const ALLOWED_ORIGIN = String(process.env.ALLOWED_ORIGIN || "").trim();

function normalizeOrigin(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";

  try {
    const parsed = new URL(raw);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return raw.replace(/\/+$/, "");
  }
}

function parseOptionalUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;

  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

const CRM_URL = parseOptionalUrl(process.env.CRM_URL);
const configuredAllowedOrigins = new Set(
  ALLOWED_ORIGIN.split(",").map((value) => normalizeOrigin(value)).filter(Boolean),
);
const isProduction = process.env.NODE_ENV === "production";
const hasCrmConfig = Boolean(CRM_URL && CRM_API_KEY);

if (process.env.CRM_URL && !CRM_URL) {
  console.warn("Ignoring invalid CRM_URL. Lead forwarding is disabled until it is fixed.");
}

if (!hasCrmConfig) {
  console.warn(
    "CRM forwarding disabled. Configure CRM_URL and CRM_API_KEY to enable POST /leads.",
  );
}

app.disable("x-powered-by");
app.set("trust proxy", 1);

function getRequestOrigin(req) {
  const forwardedProto = String(req.get("x-forwarded-proto") || "")
    .split(",")[0]
    .trim();
  const protocol = forwardedProto || req.protocol;
  const host = String(req.get("host") || "").trim();
  if (!host) return "";
  return normalizeOrigin(`${protocol}://${host}`);
}

function isAllowedOrigin(origin, req) {
  const normalizedOrigin = normalizeOrigin(origin);
  if (!normalizedOrigin) return false;

  if (configuredAllowedOrigins.has(normalizedOrigin)) {
    return true;
  }

  return normalizedOrigin === getRequestOrigin(req);
}

function withTimeout(timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  return {
    signal: controller.signal,
    clear() {
      clearTimeout(timeout);
    },
  };
}

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        objectSrc: ["'none'"],
        formAction: ["'self'", "https://www.racon.com.br"],
        frameAncestors: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdn.jsdelivr.net",
          "https://cdn.jsdelivr.net/gh",
          "https://www.googletagmanager.com",
          "https://www.google.com",
          "https://www.gstatic.com",
          "https://www.termsfeed.com",
          "https://ajax.googleapis.com",
          "https://connect.facebook.net",
          "https://snap.licdn.com",
          "https://googleads.g.doubleclick.net",
          "https://www.googleadservices.com",
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdn.jsdelivr.net",
          "https://www.termsfeed.com",
          "https://ajax.googleapis.com",
          "https://www.racon.com.br",
        ],
        styleSrcAttr: ["'unsafe-inline'"],
        imgSrc: [
          "'self'",
          "data:",
          "blob:",
          "https://www.racon.com.br",
          "https://www.google.com",
          "https://www.gstatic.com",
          "https://www.googletagmanager.com",
          "https://connect.facebook.net",
          "https://googleads.g.doubleclick.net",
          "https://www.googleadservices.com",
          "https://www.facebook.com",
        ],
        fontSrc: ["'self'", "data:", "https://fonts.gstatic.com", "https://fonts.googleapis.com"],
        connectSrc: [
          "'self'",
          "https://servicodados.ibge.gov.br",
          "https://www.racon.com.br",
          "https://www.googletagmanager.com",
          "https://*.google-analytics.com",
          "https://region1.google-analytics.com",
          "https://stats.g.doubleclick.net",
          "https://connect.facebook.net",
          "https://www.facebook.com",
          "https://googleads.g.doubleclick.net",
          "https://www.googleadservices.com",
          "https://snap.licdn.com",
          "https://www.termsfeed.com",
        ],
        frameSrc: [
          "'self'",
          "https://www.googletagmanager.com",
          "https://www.google.com",
          "https://www.gstatic.com",
          "https://googleads.g.doubleclick.net",
          "https://www.youtube.com",
        ],
        workerSrc: ["'self'", "blob:"],
        upgradeInsecureRequests: isProduction ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  }),
);

app.use(
  cors((req, callback) => {
    const origin = req.get("origin");

    if (!origin || isAllowedOrigin(origin, req)) {
      callback(null, {
        origin: true,
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: ["Content-Type"],
      });
      return;
    }

    callback(new Error("Origin not allowed by CORS"));
  }),
);

app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

app.use(
  "/assets",
  express.static(landingAssetsDir, {
    index: false,
    maxAge: "7d",
    immutable: true,
    setHeaders(res) {
      res.setHeader("X-Content-Type-Options", "nosniff");
    },
  }),
);

const leadsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many requests",
  },
});

app.use("/leads", leadsLimiter);

function normalizeText(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");
}

function normalizeEstado(value) {
  return normalizeText(value).toUpperCase();
}

function normalizeCelular(value) {
  return String(value || "").replace(/\D/g, "");
}

function normalizeEmail(value) {
  return normalizeText(value).toLowerCase();
}

function parseRendaMensal(value) {
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : NaN;
  }

  if (typeof value !== "string") {
    return NaN;
  }

  const raw = value.trim();
  if (!raw) return NaN;

  const chunks = raw.match(/\d[\d.,]*/g) || [];
  if (chunks.length === 0) return NaN;

  let normalized = chunks[chunks.length - 1].trim();
  const hasComma = normalized.includes(",");
  const hasDot = normalized.includes(".");

  if (hasComma && hasDot) {
    if (normalized.lastIndexOf(",") > normalized.lastIndexOf(".")) {
      normalized = normalized.replace(/\./g, "").replace(",", ".");
    } else {
      normalized = normalized.replace(/,/g, "");
    }
  } else if (hasComma) {
    if (/,\d{1,2}$/.test(normalized)) {
      normalized = normalized.replace(/\./g, "").replace(",", ".");
    } else {
      normalized = normalized.replace(/,/g, "");
    }
  } else if (hasDot && !/\.\d{1,2}$/.test(normalized)) {
    normalized = normalized.replace(/\./g, "");
  }

  normalized = normalized.replace(/[^\d.-]/g, "");
  const numberValue = Number(normalized);
  return Number.isFinite(numberValue) ? numberValue : NaN;
}

function pickValue(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    if (typeof value === "string" && value.trim() === "") continue;
    return value;
  }
  return "";
}

function sanitizeAdditionalFields(body) {
  const reserved = new Set([
    "nome",
    "name",
    "cidade",
    "city",
    "estado",
    "state",
    "renda_mensal",
    "monthly_income",
    "celular",
    "telefone",
    "phone",
    "email",
    "value",
    "origin",
    "origem",
    "message",
    "nextStep",
    "proximoPasso",
    "tags",
    "website",
    "company_website",
  ]);
  const out = {};

  for (const [key, value] of Object.entries(body || {})) {
    if (reserved.has(key)) continue;
    if (typeof key !== "string" || key.length === 0 || key.length > 50) continue;

    if (typeof value === "string") {
      out[key] = value.trim().slice(0, 300);
      continue;
    }

    if (typeof value === "number" && Number.isFinite(value)) {
      out[key] = value;
      continue;
    }

    if (typeof value === "boolean" || value === null) {
      out[key] = value;
    }
  }

  return out;
}

function buildValidationErrors(data) {
  const errors = [];

  if (!data.nome || data.nome.length < 2 || data.nome.length > 120) {
    errors.push("nome inválido (2-120 caracteres)");
  }

  if (!data.cidade || data.cidade.length < 2 || data.cidade.length > 120) {
    errors.push("cidade inválida (2-120 caracteres)");
  }

  if (!/^[A-Z]{2}$/.test(data.estado)) {
    errors.push("estado inválido (UF com 2 letras)");
  }

  if (!Number.isFinite(data.renda_mensal) || data.renda_mensal <= 0) {
    errors.push("renda_mensal inválida (número maior que 0)");
  }

  if (!/^\d{10,13}$/.test(data.celular)) {
    errors.push("celular inválido (somente dígitos, 10-13 caracteres)");
  }

  if (data.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
    errors.push("email inválido");
  }

  return errors;
}

function buildCrmPayload(body) {
  const source = body || {};

  const normalized = {
    nome: normalizeText(pickValue(source.nome, source.name)),
    cidade: normalizeText(pickValue(source.cidade, source.city)),
    estado: normalizeEstado(pickValue(source.estado, source.state)),
    renda_mensal: parseRendaMensal(
      pickValue(source.renda_mensal, source.monthly_income, source.value),
    ),
    celular: normalizeCelular(pickValue(source.celular, source.telefone, source.phone)),
    email: normalizeEmail(source.email),
  };

  const errors = buildValidationErrors(normalized);
  const origin = normalizeText(pickValue(source.origin, source.origem)) || "Landing Racon";
  const additionalFields = sanitizeAdditionalFields(source);
  const payload = {
    name: normalized.nome,
    phone: normalized.celular,
    origin,
    value: normalized.renda_mensal,
    nextStep: "Entrar em contato com lead da landing",
    message: [
      `Cidade: ${normalized.cidade}`,
      `Estado: ${normalized.estado}`,
      `Renda mensal: ${normalized.renda_mensal}`,
    ].join(" | "),
    nome: normalized.nome,
    cidade: normalized.cidade,
    estado: normalized.estado,
    renda_mensal: normalized.renda_mensal,
    celular: normalized.celular,
    ...additionalFields,
    received_at: new Date().toISOString(),
  };
  if (normalized.email) {
    payload.email = normalized.email;
  }

  return {
    errors,
    payload,
  };
}

function sendLandingPage(fileName) {
  return (_req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.sendFile(path.join(landingDir, fileName));
  };
}

async function fetchCitiesFromIbge(uf) {
  const request = withTimeout(8000);

  try {
    const response = await fetch(
      `https://servicodados.ibge.gov.br/api/v1/localidades/estados/${encodeURIComponent(uf)}/municipios`,
      { signal: request.signal },
    );

    if (!response.ok) {
      return [];
    }

    const payload = await response.json();
    if (!Array.isArray(payload)) {
      return [];
    }

    return [...new Set(
      payload
        .map((item) => normalizeText(item?.nome))
        .filter(Boolean),
    )].sort((a, b) => a.localeCompare(b, "pt-BR"));
  } finally {
    request.clear();
  }
}

app.get(["/", "/index.html"], sendLandingPage("index.html"));
app.get(["/racon", "/racon.html"], sendLandingPage("racon.html"));
app.get(["/eventos", "/eventos.html"], sendLandingPage("eventos.html"));
app.get(["/simulador", "/teste.html"], sendLandingPage("teste.html"));

app.get("/cities", async (req, res) => {
  const uf = normalizeEstado(req.query?.state);

  if (!/^[A-Z]{2}$/.test(uf)) {
    res.status(400).json({ error: "Invalid state" });
    return;
  }

  try {
    const cities = await fetchCitiesFromIbge(uf);
    res.status(200).json({ cities });
  } catch (error) {
    if (error?.name === "AbortError") {
      res.status(504).json({ error: "Cities request timeout" });
      return;
    }

    console.error("Cities lookup failed:", error);
    res.status(502).json({ error: "Failed to load cities" });
  }
});

app.post("/leads", async (req, res) => {
  if (!hasCrmConfig) {
    res.status(503).json({ error: "Lead collector is not configured" });
    return;
  }

  try {
    const honeypot = normalizeText(
      pickValue(req.body?.website, req.body?.company_website),
    );
    if (honeypot) {
      res.status(204).send();
      return;
    }

    const { errors, payload } = buildCrmPayload(req.body || {});
    if (errors.length > 0) {
      res.status(400).json({
        error: "Invalid payload",
        details: errors,
      });
      return;
    }

    const request = withTimeout(8000);

    let crmResponse;
    try {
      crmResponse = await fetch(new URL("/internal/leads", CRM_URL), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${CRM_API_KEY}`,
        },
        body: JSON.stringify(payload),
        signal: request.signal,
      });
    } finally {
      request.clear();
    }

    if (!crmResponse.ok) {
      res.status(502).json({
        error: "CRM request failed",
        crm_status: crmResponse.status,
      });
      return;
    }

    res.status(201).json({
      success: true,
      message: "Lead received",
    });
  } catch (error) {
    if (error?.name === "AbortError") {
      res.status(502).json({ error: "CRM request timeout" });
      return;
    }

    console.error("Internal error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
    crm_forwarding: hasCrmConfig ? "enabled" : "disabled",
  });
});

app.use((err, _req, res, _next) => {
  if (err?.type === "entity.too.large") {
    res.status(400).json({ error: "Payload too large (max 20kb)" });
    return;
  }

  if (err?.message === "Origin not allowed by CORS") {
    res.status(400).json({ error: "Invalid origin" });
    return;
  }

  console.error("Unhandled middleware error:", err);
  res.status(500).json({ error: "Internal server error" });
});

const server = app.listen(PORT, () => {
  console.log(`Lead collector running on port ${PORT}`);
});

export { app, server };
