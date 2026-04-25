import "dotenv/config";
import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import path from "node:path";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { URL, fileURLToPath } from "node:url";
import admin from "firebase-admin";

const HOST = process.env.HOST ?? "127.0.0.1";
const PORT = Number.parseInt(process.env.PORT ?? "8088", 10);
const TRUST_PROXY_HEADERS = String(process.env.TRUST_PROXY_HEADERS ?? "").trim() === "1";
const ENFORCE_HTTPS = String(process.env.ENFORCE_HTTPS ?? "").trim() === "1";
const NODE_ENV = String(process.env.NODE_ENV ?? "").trim().toLowerCase();
const IS_PRODUCTION = NODE_ENV === "production";

const SITE_ROOT = path.dirname(fileURLToPath(import.meta.url));

const PORTAL_COOKIE_NAME = process.env.CUSTOMER_SESSION_COOKIE_NAME ?? "customer_session";
const LEGACY_PORTAL_COOKIE_NAME = "portal_session";
const PORTAL_CSRF_COOKIE_NAME = process.env.CUSTOMER_CSRF_COOKIE_NAME ?? "customer_csrf";
const LEGACY_PORTAL_CSRF_COOKIE_NAME = "portal_csrf";
const ADMIN_CSRF_COOKIE_NAME = process.env.ADMIN_CSRF_COOKIE_NAME ?? "admin_csrf";
const PORTAL_COOKIE_SECRET = process.env.PORTAL_COOKIE_SECRET ?? process.env.PORTAL_COOKIE_SIGNING_SECRET ?? "";
const PORTAL_COOKIE_TTL_MS = Number.parseInt(process.env.PORTAL_COOKIE_TTL_MS ?? "1209600000", 10); // 14 days

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_CHECKOUT_PER_WINDOW = 10;
const RATE_LIMIT_MUTATION_PER_WINDOW = 30;
const RATE_LIMIT_ADMIN_AUTH_PER_WINDOW = Number.parseInt(process.env.RATE_LIMIT_ADMIN_AUTH_PER_WINDOW ?? "30", 10);

const MIME_TYPES = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".txt", "text/plain; charset=utf-8"],
  [".xml", "application/xml; charset=utf-8"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".webp", "image/webp"],
  [".svg", "image/svg+xml"],
  [".ico", "image/x-icon"],
]);

function normalizePublicBaseURL(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    url.hash = "";
    url.search = "";
    return url.toString().replace(/\/+$/, "");
  } catch {
    return null;
  }
}

const PUBLIC_BASE_URL = normalizePublicBaseURL(process.env.PUBLIC_BASE_URL);
const MARKETING_BASE_URL = normalizePublicBaseURL(process.env.MARKETING_BASE_URL) ?? PUBLIC_BASE_URL;
const APP_BASE_URL = normalizePublicBaseURL(process.env.APP_BASE_URL) ?? PUBLIC_BASE_URL;
const FIREBASE_AUTH_DEV_MODE = String(process.env.FIREBASE_AUTH_DEV_MODE ?? "").trim() === "1";
const ADMIN_SESSION_COOKIE_NAME = process.env.ADMIN_SESSION_COOKIE_NAME ?? "admin_session";
const ADMIN_SESSION_COOKIE_TTL_MS = Number.parseInt(process.env.ADMIN_SESSION_COOKIE_TTL_MS ?? "28800000", 10); // 8 hours
const SUPPORT_IMPERSONATION_TTL_MS = Number.parseInt(process.env.SUPPORT_IMPERSONATION_TTL_MS ?? "900000", 10); // 15 minutes
const ADMIN_ALLOWLIST_EMAILS = new Set(
  String(process.env.ADMIN_ALLOWLIST_EMAILS ?? "")
    .split(",")
    .map((value) => String(value).trim().toLowerCase())
    .filter(Boolean),
);

function setCommonSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Permissions-Policy",
    [
      "accelerometer=()",
      "ambient-light-sensor=()",
      "autoplay=()",
      "camera=()",
      "geolocation=()",
      "gyroscope=()",
      "magnetometer=()",
      "microphone=()",
      "payment=()",
      "usb=()",
    ].join(", "),
  );
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "img-src 'self' data:",
      "font-src 'self' https://fonts.gstatic.com data:",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "script-src 'self' 'unsafe-inline' https://www.gstatic.com https://apis.google.com",
      "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://www.googleapis.com",
      "form-action 'self'",
    ].join("; "),
  );

  const maxAge = Number.parseInt(process.env.HSTS_MAX_AGE_SECONDS ?? "", 10);
  if (Number.isFinite(maxAge) && maxAge > 0) {
    res.setHeader("Strict-Transport-Security", `max-age=${maxAge}; includeSubDomains`);
  }
}

function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body, null, 2);
  setCommonSecurityHeaders(res);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

function base64Decode(str) {
  try {
    return Buffer.from(str, "base64").toString("utf8");
  } catch {
    return null;
  }
}

function timingSafeEqualString(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function base64UrlEncode(buf) {
  return Buffer.from(buf).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecodeToBuffer(value) {
  if (typeof value !== "string" || !value) return null;
  let normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const pad = normalized.length % 4;
  if (pad === 2) normalized += "==";
  if (pad === 3) normalized += "=";
  if (pad !== 0 && pad !== 2 && pad !== 3) return null;
  try {
    return Buffer.from(normalized, "base64");
  } catch {
    return null;
  }
}

function getClientIP(req) {
  if (TRUST_PROXY_HEADERS) {
    const xff = String(req.headers["x-forwarded-for"] ?? "").trim();
    if (xff) return xff.split(",")[0].trim();
  }
  return req.socket?.remoteAddress ?? "unknown";
}

function isSecureRequest(req) {
  if (req.socket?.encrypted) return true;
  if (!TRUST_PROXY_HEADERS) return false;
  const proto = String(req.headers["x-forwarded-proto"] ?? "").toLowerCase();
  return proto.split(",")[0].trim() === "https";
}

function secureCookieForRequest(req) {
  return IS_PRODUCTION || isSecureRequest(req);
}

function mustEnv(name, { minLen = 1 } = {}) {
  const value = String(process.env[name] ?? "");
  return value.trim().length >= minLen;
}

function validateStartupConfigOrThrow() {
  if (!portalCookieKey()) {
    throw new Error("PORTAL_COOKIE_SECRET must be configured with at least 32 characters.");
  }
  if (IS_PRODUCTION) {
    if (!TRUST_PROXY_HEADERS) throw new Error("TRUST_PROXY_HEADERS=1 is required in production.");
    if (!ENFORCE_HTTPS) throw new Error("ENFORCE_HTTPS=1 is required in production.");
    if (!PUBLIC_BASE_URL?.startsWith("https://")) throw new Error("PUBLIC_BASE_URL must be https in production.");
    if (!APP_BASE_URL?.startsWith("https://")) throw new Error("APP_BASE_URL must be https in production.");
    if (ADMIN_ALLOWLIST_EMAILS.size === 0) throw new Error("ADMIN_ALLOWLIST_EMAILS must not be empty in production.");
    if (String(process.env.ADMIN_BASIC_AUTH_FALLBACK ?? "").trim() === "1") {
      throw new Error("ADMIN_BASIC_AUTH_FALLBACK must be disabled in production.");
    }
    if (FIREBASE_AUTH_DEV_MODE) throw new Error("FIREBASE_AUTH_DEV_MODE must be disabled in production.");
    if (!mustEnv("FIREBASE_SERVICE_ACCOUNT_JSON")) throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is required in production.");
    if (!mustEnv("AUTOSECOPS_COMMERCIAL_API_BASE_URL")) {
      throw new Error("AUTOSECOPS_COMMERCIAL_API_BASE_URL is required in production.");
    }
    if (!String(process.env.AUTOSECOPS_COMMERCIAL_API_BASE_URL).trim().startsWith("https://")) {
      throw new Error("AUTOSECOPS_COMMERCIAL_API_BASE_URL must use https in production.");
    }
    if (!mustEnv("AUTOSECOPS_COMMERCIAL_API_TOKEN", { minLen: 16 })) {
      throw new Error("AUTOSECOPS_COMMERCIAL_API_TOKEN is required in production.");
    }
  }
}

function parseCookies(req) {
  const header = String(req.headers.cookie ?? "");
  if (!header) return {};
  const out = {};
  for (const part of header.split(";")) {
    const [rawName, ...rest] = part.trim().split("=");
    if (!rawName) continue;
    out[rawName] = rest.join("=");
  }
  return out;
}

function appendSetCookie(res, cookie) {
  const existing = res.getHeader("Set-Cookie");
  if (!existing) {
    res.setHeader("Set-Cookie", cookie);
    return;
  }
  if (Array.isArray(existing)) {
    res.setHeader("Set-Cookie", [...existing, cookie]);
    return;
  }
  res.setHeader("Set-Cookie", [existing, cookie]);
}

function setCookie(res, name, value, { httpOnly, secure, sameSite, maxAgeSeconds, path: cookiePath } = {}) {
  const parts = [`${name}=${value ?? ""}`];
  parts.push(`Path=${cookiePath ?? "/"}`);
  parts.push("Max-Age=" + String(Math.max(0, Number(maxAgeSeconds ?? 0))));
  if (httpOnly) parts.push("HttpOnly");
  if (secure) parts.push("Secure");
  parts.push(`SameSite=${sameSite ?? "Lax"}`);
  appendSetCookie(res, parts.join("; "));
}

function clearCookie(res, name, { secure } = {}) {
  setCookie(res, name, "", { httpOnly: true, secure, sameSite: "Lax", maxAgeSeconds: 0 });
}

function portalCookieKey() {
  if (!PORTAL_COOKIE_SECRET || PORTAL_COOKIE_SECRET.trim().length < 32) return null;
  return crypto.createHash("sha256").update(PORTAL_COOKIE_SECRET.trim(), "utf8").digest();
}

function encryptPortalSession(session) {
  const key = portalCookieKey();
  if (!key) return null;
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const plaintext = Buffer.from(JSON.stringify(session), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return base64UrlEncode(Buffer.concat([nonce, tag, ciphertext]));
}

function decryptPortalSession(value) {
  const key = portalCookieKey();
  if (!key) return null;
  const raw = base64UrlDecodeToBuffer(value);
  if (!raw || raw.length < 12 + 16 + 1) return null;
  const nonce = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const parsed = JSON.parse(plaintext.toString("utf8"));
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function loadPortalSession(req, { requireTenant = true } = {}) {
  const cookies = parseCookies(req);
  const raw = cookies[PORTAL_COOKIE_NAME] || cookies[LEGACY_PORTAL_COOKIE_NAME];
  if (!raw) return null;
  const session = decryptPortalSession(raw);
  if (!session) return null;
  if (requireTenant && (typeof session.tenantKey !== "string" || !session.tenantKey.trim())) return null;
  if (session.tenantKey !== undefined && typeof session.tenantKey !== "string") return null;
  if (typeof session.firebaseUID !== "string" || !session.firebaseUID.trim()) return null;
  if (typeof session.email !== "string" || !session.email.trim()) return null;
  if (typeof session.exp !== "number" || !Number.isFinite(session.exp)) return null;
  if (Date.now() > session.exp) return null;
  if (session.supportMode === true) {
    if (typeof session.impersonatedByUID !== "string" || !session.impersonatedByUID.trim()) return null;
    if (typeof session.impersonatedByEmail !== "string" || !session.impersonatedByEmail.trim()) return null;
  }
  if (typeof session.csrf !== "string" || !session.csrf.trim()) return null;
  if (session.checkoutId !== undefined && typeof session.checkoutId !== "string") return null;
  return session;
}

function savePortalSession(req, res, sessionInput = {}) {
  const secure = secureCookieForRequest(req);
  const csrf = sessionInput.csrf || base64UrlEncode(crypto.randomBytes(18));
  const session = {
    tenantKey: typeof sessionInput.tenantKey === "string" && sessionInput.tenantKey.trim() ? sessionInput.tenantKey.trim() : undefined,
    checkoutId: typeof sessionInput.checkoutId === "string" && sessionInput.checkoutId.trim() ? sessionInput.checkoutId.trim() : undefined,
    firebaseUID: String(sessionInput.firebaseUID ?? "").trim(),
    email: String(sessionInput.email ?? "").trim().toLowerCase(),
    role: String(sessionInput.role ?? "").trim() || undefined,
    permissions: Array.isArray(sessionInput.permissions) ? sessionInput.permissions : undefined,
    supportMode: sessionInput.supportMode === true ? true : undefined,
    supportReason: String(sessionInput.supportReason ?? "").trim() || undefined,
    impersonatedByUID: String(sessionInput.impersonatedByUID ?? "").trim() || undefined,
    impersonatedByEmail: String(sessionInput.impersonatedByEmail ?? "").trim().toLowerCase() || undefined,
    impersonatingTenantKey: String(sessionInput.impersonatingTenantKey ?? "").trim() || undefined,
    csrf,
    exp: Date.now() + Math.max(60_000, PORTAL_COOKIE_TTL_MS),
  };
  if (!session.firebaseUID || !session.email) return false;
  const encrypted = encryptPortalSession(session);
  if (!encrypted) return false;

  setCookie(res, PORTAL_COOKIE_NAME, encrypted, {
    httpOnly: true,
    secure,
    sameSite: "Lax",
    maxAgeSeconds: Math.floor(PORTAL_COOKIE_TTL_MS / 1000),
    path: "/portal",
  });
  setCookie(res, PORTAL_CSRF_COOKIE_NAME, csrf, {
    httpOnly: false,
    secure,
    sameSite: "Lax",
    maxAgeSeconds: Math.floor(PORTAL_COOKIE_TTL_MS / 1000),
    path: "/portal",
  });
  return true;
}

function clearPortalSession(req, res) {
  const secure = secureCookieForRequest(req);
  setCookie(res, PORTAL_COOKIE_NAME, "", { httpOnly: true, secure, sameSite: "Lax", maxAgeSeconds: 0, path: "/portal" });
  setCookie(res, LEGACY_PORTAL_COOKIE_NAME, "", { httpOnly: true, secure, sameSite: "Lax", maxAgeSeconds: 0, path: "/portal" });
  setCookie(res, PORTAL_CSRF_COOKIE_NAME, "", { httpOnly: false, secure, sameSite: "Lax", maxAgeSeconds: 0, path: "/portal" });
  setCookie(res, LEGACY_PORTAL_CSRF_COOKIE_NAME, "", { httpOnly: false, secure, sameSite: "Lax", maxAgeSeconds: 0, path: "/portal" });
}

function loadAdminSession(req) {
  const raw = parseCookies(req)[ADMIN_SESSION_COOKIE_NAME];
  if (!raw) return null;
  const session = decryptPortalSession(raw);
  if (!session || typeof session !== "object") return null;
  if (typeof session.firebaseUID !== "string" || !session.firebaseUID.trim()) return null;
  if (typeof session.email !== "string" || !session.email.trim()) return null;
  if (!Array.isArray(session.roles) || session.roles.length === 0) return null;
  if (typeof session.csrf !== "string" || !session.csrf.trim()) return null;
  if (typeof session.exp !== "number" || !Number.isFinite(session.exp) || Date.now() > session.exp) return null;
  return session;
}

function saveAdminSession(req, res, { firebaseUID, email, roles }) {
  const secure = secureCookieForRequest(req);
  const csrf = base64UrlEncode(crypto.randomBytes(18));
  const session = {
    firebaseUID: String(firebaseUID ?? "").trim(),
    email: String(email ?? "").trim().toLowerCase(),
    roles: Array.isArray(roles) ? roles.map((r) => String(r).trim()).filter(Boolean) : [],
    csrf,
    exp: Date.now() + Math.max(60_000, ADMIN_SESSION_COOKIE_TTL_MS),
  };
  if (!session.firebaseUID || !session.email || session.roles.length === 0) return false;
  const encrypted = encryptPortalSession(session);
  if (!encrypted) return false;
  setCookie(res, ADMIN_SESSION_COOKIE_NAME, encrypted, {
    httpOnly: true,
    secure,
    sameSite: "Lax",
    maxAgeSeconds: Math.floor(ADMIN_SESSION_COOKIE_TTL_MS / 1000),
    path: "/admin",
  });
  setCookie(res, ADMIN_CSRF_COOKIE_NAME, csrf, {
    httpOnly: false,
    secure,
    sameSite: "Lax",
    maxAgeSeconds: Math.floor(ADMIN_SESSION_COOKIE_TTL_MS / 1000),
    path: "/admin",
  });
  return true;
}

function clearAdminSession(req, res) {
  setCookie(res, ADMIN_SESSION_COOKIE_NAME, "", {
    httpOnly: true,
    secure: secureCookieForRequest(req),
    sameSite: "Lax",
    maxAgeSeconds: 0,
    path: "/admin",
  });
  setCookie(res, ADMIN_CSRF_COOKIE_NAME, "", {
    httpOnly: false,
    secure: secureCookieForRequest(req),
    sameSite: "Lax",
    maxAgeSeconds: 0,
    path: "/admin",
  });
}

const rateBuckets = {
  checkout: new Map(),
  mutation: new Map(),
  admin_auth: new Map(),
  firebase_session: new Map(),
};

function allowRate(bucketName, key, limit) {
  const now = Date.now();
  const bucket = rateBuckets[bucketName];
  if (!bucket) return true;
  if (bucket.size > 5000) {
    for (const [k, v] of bucket.entries()) {
      if (!v || now >= v.resetAt) bucket.delete(k);
    }
  }
  const item = bucket.get(key);
  if (!item || now >= item.resetAt) {
    bucket.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (item.count >= limit) return false;
  item.count += 1;
  bucket.set(key, item);
  return true;
}

let firebaseApp = null;

function firebasePublicConfig() {
  const config = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    appId: process.env.FIREBASE_APP_ID,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  };
  if (Object.values(config).every((v) => typeof v === "string" && v.trim())) return config;
  return null;
}

function firebaseAdminApp() {
  if (firebaseApp) return firebaseApp;
  if (FIREBASE_AUTH_DEV_MODE && String(process.env.NODE_ENV ?? "").toLowerCase() !== "production") return null;

  const projectId = String(process.env.FIREBASE_PROJECT_ID ?? "").trim();
  const serviceAccountJSON = String(process.env.FIREBASE_SERVICE_ACCOUNT_JSON ?? "").trim();
  const options = {};
  if (projectId) options.projectId = projectId;
  if (serviceAccountJSON) {
    options.credential = admin.credential.cert(JSON.parse(serviceAccountJSON));
  } else {
    options.credential = admin.credential.applicationDefault();
  }
  firebaseApp = admin.apps.length ? admin.app() : admin.initializeApp(options);
  return firebaseApp;
}

async function verifyFirebaseToken(idToken) {
  const token = String(idToken ?? "").trim();
  if (!token) {
    const err = new Error("missing Firebase ID token");
    err.status = 400;
    throw err;
  }
  if (FIREBASE_AUTH_DEV_MODE && String(process.env.NODE_ENV ?? "").toLowerCase() !== "production") {
    return {
      uid: token.startsWith("dev-admin") ? "dev-admin" : "dev-customer",
      email: token.startsWith("dev-admin") ? "admin@singularityrd.com" : "customer@example.com",
      email_verified: true,
      admin: token.startsWith("dev-admin"),
      roles: token.startsWith("dev-admin") ? ["singularity_admin"] : [],
    };
  }
  return firebaseAdminApp().auth().verifyIdToken(token, true);
}

function adminRolesFromClaims(claims) {
  const roles = new Set();
  if (claims?.admin === true || claims?.singularity_admin === true) roles.add("singularity_admin");
  for (const value of [claims?.role, claims?.admin_role]) {
    if (typeof value === "string" && value.trim()) roles.add(value.trim());
  }
  if (Array.isArray(claims?.roles)) {
    for (const role of claims.roles) {
      if (typeof role === "string" && role.trim()) roles.add(role.trim());
    }
  }
  const allowed = new Set(["singularity_admin", "support", "billing_ops", "security_ops", "read_only"]);
  return [...roles].filter((role) => allowed.has(role));
}

function isAdminAllowlisted(email) {
  if (ADMIN_ALLOWLIST_EMAILS.size === 0) return !IS_PRODUCTION;
  return ADMIN_ALLOWLIST_EMAILS.has(String(email ?? "").trim().toLowerCase());
}

function adminBasicAuthFallbackAllowed() {
  return !IS_PRODUCTION && String(process.env.ADMIN_BASIC_AUTH_FALLBACK ?? "").trim() === "1";
}

function hasPermission(session, permission) {
  return Array.isArray(session?.permissions) && session.permissions.includes(permission);
}

function hasAdminRole(session, allowedRoles = []) {
  if (!session || !Array.isArray(session.roles)) return false;
  const current = new Set(session.roles.map((r) => String(r).trim()));
  return allowedRoles.some((role) => current.has(role));
}

function requiredAdminRolesForRoute(pathname) {
  if (pathname === "/admin/api/impersonation/start" || pathname === "/admin/api/impersonation/revoke") {
    return ["singularity_admin", "support"];
  }
  if (pathname === "/admin/api/webhooks/replay") {
    return ["singularity_admin", "support", "security_ops"];
  }
  if (
    pathname === "/admin/api/tenants" ||
    pathname === "/admin/api/webhooks/events" ||
    pathname === "/admin/api/audit/events" ||
    pathname === "/admin/api/session"
  ) {
    return ["singularity_admin", "support", "billing_ops", "security_ops", "read_only"];
  }
  return null;
}

function buildCustomerActorPayload(session) {
  return {
    firebase_uid: session.firebaseUID,
    email: session.email,
    role: session.role ?? "",
  };
}

function buildAdminActorPayload(session) {
  return {
    admin_firebase_uid: session.firebaseUID,
    admin_email: session.email,
    admin_roles: Array.isArray(session.roles) ? session.roles : [],
  };
}

function requireBasicAuth(req, res) {
  const expectedUser = process.env.ADMIN_BASIC_AUTH_USER;
  const expectedPass = process.env.ADMIN_BASIC_AUTH_PASS;

  if (!expectedUser || !expectedPass) {
    sendJson(res, 503, {
      ok: false,
      error: "Admin portal is not configured.",
      details: ["Set ADMIN_BASIC_AUTH_USER and ADMIN_BASIC_AUTH_PASS in the server environment."],
    });
    return false;
  }

  const ip = getClientIP(req);
  if (!allowRate("admin_auth", ip, RATE_LIMIT_ADMIN_AUTH_PER_WINDOW)) {
    sendJson(res, 429, { ok: false, error: "Too many attempts. Try again shortly." });
    return false;
  }

  const auth = req.headers.authorization ?? "";
  if (!auth.startsWith("Basic ")) {
    setCommonSecurityHeaders(res);
    res.writeHead(401, {
      "WWW-Authenticate": 'Basic realm="silanding admin", charset="UTF-8"',
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
    });
    res.end("Authentication required.");
    return false;
  }

  const decoded = base64Decode(auth.slice("Basic ".length).trim());
  if (!decoded) {
    setCommonSecurityHeaders(res);
    res.writeHead(401, {
      "WWW-Authenticate": 'Basic realm="silanding admin", charset="UTF-8"',
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
    });
    res.end("Invalid Authorization header.");
    return false;
  }

  const sepIndex = decoded.indexOf(":");
  const user = sepIndex === -1 ? decoded : decoded.slice(0, sepIndex);
  const pass = sepIndex === -1 ? "" : decoded.slice(sepIndex + 1);

  const userOk = timingSafeEqualString(user, expectedUser);
  const passOk = timingSafeEqualString(pass, expectedPass);

  if (!userOk || !passOk) {
    setCommonSecurityHeaders(res);
    res.writeHead(401, {
      "WWW-Authenticate": 'Basic realm="silanding admin", charset="UTF-8"',
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
    });
    res.end("Invalid credentials.");
    return false;
  }

  return true;
}

function resolveSafePath(urlPathname) {
  let decodedPath = null;
  try {
    decodedPath = decodeURIComponent(urlPathname);
  } catch {
    return null;
  }
  decodedPath = decodedPath.replaceAll("\\", "/");
  const normalized = path.posix.normalize(decodedPath);
  if (normalized.includes(":")) return null;

  const relative = normalized.replace(/^\/+/, "");
  const fsPath = path.join(SITE_ROOT, relative);
  const resolved = path.resolve(fsPath);
  const resolvedRoot = path.resolve(SITE_ROOT);
  if (!resolved.startsWith(resolvedRoot + path.sep) && resolved !== resolvedRoot) return null;
  return resolved;
}

async function serveFile(req, res, fsPath, { cacheControl } = {}) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    setCommonSecurityHeaders(res);
    res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    res.end("Method Not Allowed");
    return;
  }

  const ext = path.extname(fsPath).toLowerCase();
  const contentType = MIME_TYPES.get(ext) ?? "application/octet-stream";

  try {
    const st = await stat(fsPath);
    if (st.isDirectory()) {
      return serveFile(req, res, path.join(fsPath, "index.html"), { cacheControl });
    }

    setCommonSecurityHeaders(res);
    res.writeHead(200, {
      "Content-Type": contentType,
      "Content-Length": st.size,
      "Cache-Control": cacheControl ?? "public, max-age=300",
    });
    if (req.method === "HEAD") {
      res.end();
      return;
    }
    createReadStream(fsPath).pipe(res);
    return;
  } catch {
    setCommonSecurityHeaders(res);
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found.");
  }
}

async function readJsonBody(req, { maxBytes = 512 * 1024 } = {}) {
  let buf = "";
  for await (const chunk of req) {
    buf += chunk.toString("utf8");
    if (buf.length > maxBytes) {
      const err = new Error("Payload too large");
      err.code = "PAYLOAD_TOO_LARGE";
      throw err;
    }
  }
  if (!buf.trim()) return null;
  return JSON.parse(buf);
}

async function readFormBody(req, { maxBytes = 64 * 1024 } = {}) {
  let buf = "";
  for await (const chunk of req) {
    buf += chunk.toString("utf8");
    if (buf.length > maxBytes) {
      const err = new Error("Payload too large");
      err.code = "PAYLOAD_TOO_LARGE";
      throw err;
    }
  }
  const params = new URLSearchParams(buf);
  const out = {};
  for (const [k, v] of params.entries()) out[k] = v;
  return out;
}

function requestOrigin(req) {
  if (PUBLIC_BASE_URL) return PUBLIC_BASE_URL;

  const nodeEnv = String(process.env.NODE_ENV ?? "").toLowerCase();
  if (nodeEnv === "production") return null;

  const proto = TRUST_PROXY_HEADERS ? String(req.headers["x-forwarded-proto"] ?? "").toLowerCase() : "http";
  const host = String(req.headers.host ?? "").trim();
  if (!host) return null;
  const normalizedProto = proto.split(",")[0].trim() || "http";
  return `${normalizedProto}://${host}`;
}

function appOrigin(req) {
  if (APP_BASE_URL) return APP_BASE_URL;
  return requestOrigin(req);
}

function ensurePortalConfiguredOr503(res) {
  if (!portalCookieKey()) {
    sendJson(res, 503, {
      ok: false,
      error: "Portal is not configured.",
      details: ["Set PORTAL_COOKIE_SECRET to a long random secret (32+ chars)."],
    });
    return false;
  }
  return true;
}

function validateEmail(value) {
  const trimmed = String(value ?? "").trim().toLowerCase();
  if (!trimmed || trimmed.length > 254) return null;
  if (!trimmed.includes("@")) return null;
  return trimmed;
}

function validateOrg(value) {
  const trimmed = String(value ?? "").trim();
  if (!trimmed || trimmed.length > 160) return null;
  return trimmed;
}

function validatePackage(value) {
  const v = String(value ?? "").trim().toLowerCase();
  if (v === "core" || v === "pro") return v;
  return null;
}

function validateCycle(value) {
  const v = String(value ?? "").trim().toLowerCase();
  if (v === "monthly" || v === "yearly") return v;
  return null;
}

function validateSeats(value) {
  const n = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(n) || n < 1 || n > 100_000) return null;
  return n;
}

function commercialAuthHeaders() {
  const token =
    process.env.AUTOSECOPS_COMMERCIAL_API_TOKEN ??
    process.env.AUTOSECOPS_COMMERCIAL_TOKEN ??
    process.env.AUTOSECOPS_COMMERCIAL_API_TOKEN_BEARER;
  if (!token) return {};

  const headerName = process.env.AUTOSECOPS_COMMERCIAL_AUTH_HEADER ?? "Authorization";
  const scheme = process.env.AUTOSECOPS_COMMERCIAL_AUTH_SCHEME ?? "Bearer";

  if (scheme) return { [headerName]: `${scheme} ${token}` };
  return { [headerName]: token };
}

function commercialConfigOrError(res, { requiredPathEnv } = {}) {
  const baseUrl = process.env.AUTOSECOPS_COMMERCIAL_API_BASE_URL;
  if (!baseUrl) {
    sendJson(res, 501, {
      ok: false,
      error: "Commercial API not configured.",
      details: ["Set AUTOSECOPS_COMMERCIAL_API_BASE_URL and AUTOSECOPS_COMMERCIAL_API_TOKEN (server-side only)."],
    });
    return null;
  }

  const token =
    process.env.AUTOSECOPS_COMMERCIAL_API_TOKEN ??
    process.env.AUTOSECOPS_COMMERCIAL_TOKEN ??
    process.env.AUTOSECOPS_COMMERCIAL_API_TOKEN_BEARER;
  if (!token) {
    sendJson(res, 501, {
      ok: false,
      error: "Commercial API token not configured.",
      details: ["Set AUTOSECOPS_COMMERCIAL_API_TOKEN (server-side only)."],
    });
    return null;
  }

  if (requiredPathEnv && !process.env[requiredPathEnv]) {
    sendJson(res, 501, {
      ok: false,
      error: "Commercial API endpoint not configured.",
      details: [`Set ${requiredPathEnv} to the correct commercial endpoint path.`],
    });
    return null;
  }

  try {
    const url = new URL(baseUrl);
    url.hash = "";
    url.search = "";
    return { baseUrl: url.toString().replace(/\/+$/, "") };
  } catch {
    sendJson(res, 501, {
      ok: false,
      error: "Commercial API base URL invalid.",
      details: ["AUTOSECOPS_COMMERCIAL_API_BASE_URL must be a valid URL."],
    });
    return null;
  }
}

function httpRequest(url, { method, headers, body }) {
  const lib = url.protocol === "https:" ? https : http;
  const allowInsecureLocalTLS =
    String(process.env.AUTOSECOPS_COMMERCIAL_API_ALLOW_INSECURE_TLS ?? "").trim() === "1" &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1");

  return new Promise((resolve, reject) => {
    const req = lib.request(
      url,
      {
        method,
        headers,
        rejectUnauthorized: !allowInsecureLocalTLS,
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            bodyText: data,
          });
        });
      },
    );

    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

async function commercialJson(url, { method, jsonBody }) {
  const headers = {
    Accept: "application/json",
    ...commercialAuthHeaders(),
  };

  let body;
  if (jsonBody !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(jsonBody);
  }

  const resp = await httpRequest(url, { method, headers, body });
  let json = null;
  try {
    json = resp.bodyText ? JSON.parse(resp.bodyText) : null;
  } catch {
    // ignore parse errors
  }
  return { ...resp, json };
}

async function commercialAuthMe({ firebaseUID, email, tenantKey, portalType }) {
  const baseUrl = process.env.AUTOSECOPS_COMMERCIAL_API_BASE_URL;
  if (!baseUrl) throw new Error("Commercial API not configured");
  const url = new URL("/api/v1/commercial/auth/me", baseUrl);
  url.searchParams.set("firebase_uid", firebaseUID);
  if (email) url.searchParams.set("email", email);
  if (tenantKey) url.searchParams.set("tenant_key", tenantKey);
  if (portalType) url.searchParams.set("portal_type", portalType);
  const resp = await commercialJson(url, { method: "GET" });
  if (resp.status < 200 || resp.status >= 300 || !resp.json) {
    const err = new Error(resp.json?.error || `commercial auth/me failed: HTTP ${resp.status}`);
    err.status = resp.status;
    err.payload = resp.json ?? resp.bodyText;
    throw err;
  }
  return resp.json;
}

async function bootstrapCommercialOwner({ tenantKey, firebaseUID, email, checkoutId }) {
  const baseUrl = process.env.AUTOSECOPS_COMMERCIAL_API_BASE_URL;
  if (!baseUrl) throw new Error("Commercial API not configured");
  const url = new URL("/api/v1/commercial/tenant/memberships/bootstrap-owner", baseUrl);
  const resp = await commercialJson(url, {
    method: "POST",
    jsonBody: {
      tenant_key: tenantKey,
      firebase_uid: firebaseUID,
      email,
      checkout_id: checkoutId,
    },
  });
  if (resp.status < 200 || resp.status >= 300 || !resp.json) {
    const err = new Error(resp.json?.error || `commercial bootstrap failed: HTTP ${resp.status}`);
    err.status = resp.status;
    err.payload = resp.json ?? resp.bodyText;
    throw err;
  }
  return resp.json;
}

function normalizeListPayload(json) {
  if (Array.isArray(json)) return json;
  if (!json || typeof json !== "object") return [];
  for (const key of ["tenants", "events", "items", "data", "results"]) {
    if (Array.isArray(json[key])) return json[key];
  }
  return [];
}

async function handleAuth(req, res, pathname) {
  if (req.method === "GET" && pathname === "/auth/firebase-config") {
    const config = firebasePublicConfig();
    if (!config && !FIREBASE_AUTH_DEV_MODE) {
      sendJson(res, 503, { ok: false, error: "Firebase client config is not configured." });
      return true;
    }
    sendJson(res, 200, {
      ok: true,
      dev_mode: FIREBASE_AUTH_DEV_MODE && String(process.env.NODE_ENV ?? "").toLowerCase() !== "production",
      firebase: config,
    });
    return true;
  }
  return false;
}

async function handlePortalAuth(req, res, pathname) {
  if (req.method !== "POST" || pathname !== "/portal/auth/session") return false;
  if (!ensurePortalConfiguredOr503(res)) return true;
  if (!allowRate("firebase_session", getClientIP(req), RATE_LIMIT_ADMIN_AUTH_PER_WINDOW)) {
    sendJson(res, 429, { ok: false, error: "Too many attempts. Try again shortly." });
    return true;
  }
  let body;
  try {
    body = await readJsonBody(req, { maxBytes: 64 * 1024 });
  } catch {
    sendJson(res, 400, { ok: false, error: "Invalid JSON body." });
    return true;
  }
  try {
    const claims = await verifyFirebaseToken(body?.id_token);
    const email = validateEmail(claims.email);
    if (!email || claims.email_verified !== true) {
      sendJson(res, 403, { ok: false, error: "A verified Firebase email is required." });
      return true;
    }
    const tenantKeyHint = String(body?.tenant_key ?? "").trim();
    let me = null;
    try {
      me = await commercialAuthMe({ firebaseUID: claims.uid, email, tenantKey: tenantKeyHint, portalType: "customer" });
    } catch (err) {
      if (err.status !== 404) throw err;
      if (tenantKeyHint) {
        sendJson(res, 403, { ok: false, error: "Tenant access is not allowed for this account." });
        return true;
      }
    }
    if (!savePortalSession(req, res, {
      tenantKey: me?.tenant_key || undefined,
      firebaseUID: claims.uid,
      email,
      role: me?.role || undefined,
      permissions: me?.permissions || undefined,
    })) {
      sendJson(res, 503, { ok: false, error: "Customer session could not be created." });
      return true;
    }
    sendJson(res, 200, {
      ok: true,
      firebase_uid: claims.uid,
      email,
      tenant_key: me?.tenant_key || "",
      role: me?.role || "",
      permissions: me?.permissions || [],
    });
  } catch (err) {
    sendJson(res, err.status === 404 ? 404 : 401, { ok: false, error: err.message || "Firebase authentication failed." });
  }
  return true;
}

async function handleAdminAuth(req, res, pathname) {
  if (req.method !== "POST" || pathname !== "/admin/auth/session") return false;
  if (!ensurePortalConfiguredOr503(res)) return true;
  if (!allowRate("firebase_session", getClientIP(req), RATE_LIMIT_ADMIN_AUTH_PER_WINDOW)) {
    sendJson(res, 429, { ok: false, error: "Too many attempts. Try again shortly." });
    return true;
  }
  let body;
  try {
    body = await readJsonBody(req, { maxBytes: 64 * 1024 });
  } catch {
    sendJson(res, 400, { ok: false, error: "Invalid JSON body." });
    return true;
  }
  try {
    const claims = await verifyFirebaseToken(body?.id_token);
    const email = validateEmail(claims.email);
    const roles = adminRolesFromClaims(claims);
    if (!email || claims.email_verified !== true || roles.length === 0 || !isAdminAllowlisted(email)) {
      sendJson(res, 403, { ok: false, error: "Admin access is not allowed for this account." });
      return true;
    }
    if (!saveAdminSession(req, res, { firebaseUID: claims.uid, email, roles })) {
      sendJson(res, 503, { ok: false, error: "Admin session could not be created." });
      return true;
    }
    sendJson(res, 200, { ok: true, firebase_uid: claims.uid, email, roles });
  } catch (err) {
    sendJson(res, 401, { ok: false, error: err.message || "Firebase authentication failed." });
  }
  return true;
}

async function handlePortal(req, res, pathname) {
  if (!ensurePortalConfiguredOr503(res)) return;

  if (await handlePortalAuth(req, res, pathname)) return;

  if (req.method === "POST" && (pathname === "/portal/start" || pathname === "/portal/start/")) {
    const session = loadPortalSession(req, { requireTenant: false });
    if (!session) {
      res.writeHead(303, { Location: "/portal/login/?next=/portal/start/", "Cache-Control": "no-store" });
      res.end();
      return;
    }
    const ip = getClientIP(req);
    if (!allowRate("checkout", ip, RATE_LIMIT_CHECKOUT_PER_WINDOW)) {
      sendJson(res, 429, { ok: false, error: "Too many requests. Try again shortly." });
      return;
    }

    const cfg = commercialConfigOrError(res);
    if (!cfg) return;

    let form;
    try {
      form = await readFormBody(req);
    } catch (err) {
      if (err?.code === "PAYLOAD_TOO_LARGE") {
        sendJson(res, 413, { ok: false, error: "Payload too large." });
        return;
      }
      sendJson(res, 400, { ok: false, error: "Invalid form body." });
      return;
    }

    const organizationName = validateOrg(form.org ?? form.organization_name);
    const adminEmail = validateEmail(session.email);
    const packageCode = validatePackage(form.package ?? form.package_code);
    const billingCycle = validateCycle(form.cycle ?? form.billing_cycle);
    const seatsPurchased = validateSeats(form.seats ?? form.seats_purchased);

    if (!organizationName || !adminEmail || !packageCode || !billingCycle || !seatsPurchased) {
      sendJson(res, 400, {
        ok: false,
        error: "Invalid input.",
        details: ["org, email, package, cycle, seats are required."],
      });
      return;
    }

    const origin = appOrigin(req);
    if (!origin) {
      sendJson(res, 503, {
        ok: false,
        error: "PUBLIC_BASE_URL is not configured.",
        details: ["Set PUBLIC_BASE_URL (e.g. https://singularityrd.com or http://localhost:8088)."],
      });
      return;
    }

    const checkoutUrl = new URL("/api/v1/commercial/checkout", cfg.baseUrl);
    const payload = {
      organization_name: organizationName,
      admin_email: adminEmail,
      package_code: packageCode,
      billing_cycle: billingCycle,
      seats_purchased: seatsPurchased,
      success_url: `${origin}/portal/success/`,
      cancel_url: `${origin}/portal/cancel/`,
    };

    try {
      const resp = await commercialJson(checkoutUrl, { method: "POST", jsonBody: payload });
      if (resp.status < 200 || resp.status >= 300 || !resp.json) {
        sendJson(res, 502, {
          ok: false,
          error: "Checkout creation failed.",
          details: [`HTTP ${resp.status}`],
          body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
        });
        return;
      }

      const tenantKey = String(resp.json.tenant_key ?? "").trim();
      const redirectURL = String(resp.json.redirect_url ?? "").trim();
      const checkoutId = String(resp.json.checkout_id ?? "").trim();
      if (!tenantKey || !redirectURL) {
        sendJson(res, 502, { ok: false, error: "Commercial API returned an invalid checkout response." });
        return;
      }

      const ok = savePortalSession(req, res, {
        ...session,
        tenantKey,
        checkoutId,
      });
      if (!ok) {
        sendJson(res, 503, { ok: false, error: "Portal session could not be created." });
        return;
      }

      res.writeHead(303, { Location: redirectURL, "Cache-Control": "no-store" });
      res.end();
      return;
    } catch (err) {
      sendJson(res, 502, { ok: false, error: "Commercial API request error.", details: [String(err)] });
      return;
    }
  }

  if (req.method === "POST" && pathname === "/portal/logout") {
    clearPortalSession(req, res);
    res.writeHead(303, { Location: "/portal/login/", "Cache-Control": "no-store" });
    res.end();
    return;
  }

  if (req.method === "GET" && (pathname === "/portal/start" || pathname === "/portal/start/")) {
    const session = loadPortalSession(req, { requireTenant: false });
    if (!session) {
      res.writeHead(303, { Location: "/portal/login/?next=/portal/start/", "Cache-Control": "no-store" });
      res.end();
      return;
    }
  }

  if (pathname === "/portal/dashboard" || pathname === "/portal/dashboard/") {
    const session = loadPortalSession(req);
    if (!session) {
      res.writeHead(303, { Location: "/portal/login/?next=/portal/dashboard/", "Cache-Control": "no-store" });
      res.end();
      return;
    }
  }

  if (pathname.startsWith("/portal/api/")) {
    setCommonSecurityHeaders(res);
    const session = loadPortalSession(req, { requireTenant: pathname !== "/portal/api/session" });
    if (!session) {
      sendJson(res, 401, { ok: false, error: "Not signed in." });
      return;
    }

    const cfg = commercialConfigOrError(res);
    if (!cfg) return;

    const csrfHeader = String(req.headers["x-csrf-token"] ?? "").trim();
    const cookies = parseCookies(req);
    const csrfCookie = String(cookies[PORTAL_CSRF_COOKIE_NAME] ?? "").trim();
    const csrfOk = csrfHeader && csrfCookie && session.csrf && csrfHeader === csrfCookie && csrfHeader === session.csrf;

    const ip = getClientIP(req);
    if (req.method !== "GET" && !allowRate("mutation", ip, RATE_LIMIT_MUTATION_PER_WINDOW)) {
      sendJson(res, 429, { ok: false, error: "Too many requests. Try again shortly." });
      return;
    }

    if (req.method === "GET" && pathname === "/portal/api/session") {
      sendJson(res, 200, {
        ok: true,
        firebase_uid: session.firebaseUID,
        email: session.email,
        tenant_key: session.tenantKey ?? "",
        checkout_id: session.checkoutId ?? "",
        role: session.role ?? "",
        permissions: session.permissions ?? [],
      });
      return;
    }

    if (req.method === "POST" && pathname === "/portal/api/bootstrap-owner") {
      if (!csrfOk) {
        sendJson(res, 403, { ok: false, error: "CSRF validation failed." });
        return;
      }
      if (!session.tenantKey) {
        sendJson(res, 400, { ok: false, error: "Tenant session is required." });
        return;
      }
      try {
        const boot = await bootstrapCommercialOwner({
          tenantKey: session.tenantKey,
          firebaseUID: session.firebaseUID,
          email: session.email,
          checkoutId: session.checkoutId ?? "",
        });
        const ok = savePortalSession(req, res, {
          ...session,
          role: boot.role,
          permissions: boot.permissions,
        });
        if (!ok) {
          sendJson(res, 503, { ok: false, error: "Customer session could not be refreshed." });
          return;
        }
        sendJson(res, 200, { ok: true, ...boot });
      } catch (err) {
        sendJson(res, err.status === 403 ? 403 : 502, { ok: false, error: err.message, body: err.payload });
      }
      return;
    }

    if (req.method === "GET" && pathname === "/portal/api/subscription") {
      const url = new URL("/api/v1/commercial/tenant/subscription", cfg.baseUrl);
      url.searchParams.set("tenant_key", session.tenantKey);
      url.searchParams.set("firebase_uid", session.firebaseUID);
      url.searchParams.set("email", session.email);
      const resp = await commercialJson(url, { method: "GET" });
      if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
        sendJson(res, 200, { ok: true, ...resp.json, tenant_key: resp.json.tenant_key ?? session.tenantKey });
        return;
      }
      sendJson(res, 502, {
        ok: false,
        error: "Commercial API request failed.",
        details: [`HTTP ${resp.status}`],
        body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
      });
      return;
    }

    if (req.method === "GET" && pathname === "/portal/api/device-licenses") {
      const url = new URL("/api/v1/commercial/device-licenses", cfg.baseUrl);
      url.searchParams.set("tenant_key", session.tenantKey);
      url.searchParams.set("firebase_uid", session.firebaseUID);
      url.searchParams.set("email", session.email);
      const resp = await commercialJson(url, { method: "GET" });
      if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
        sendJson(res, 200, { ok: true, ...resp.json, tenant_key: resp.json.tenant_key ?? session.tenantKey });
        return;
      }
      sendJson(res, 502, {
        ok: false,
        error: "Commercial API request failed.",
        details: [`HTTP ${resp.status}`],
        body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
      });
      return;
    }

    if (req.method === "POST" && pathname === "/portal/api/device-licenses/issue") {
      if (!csrfOk) {
        sendJson(res, 403, { ok: false, error: "CSRF validation failed." });
        return;
      }
      if (!hasPermission(session, "device_license:issue")) {
        sendJson(res, 403, { ok: false, error: "Your role cannot issue device licenses." });
        return;
      }
      let body;
      try {
        body = await readJsonBody(req, { maxBytes: 32 * 1024 });
      } catch {
        sendJson(res, 400, { ok: false, error: "Invalid JSON body." });
        return;
      }
      const count = validateSeats(body?.count);
      if (!count || count > 500) {
        sendJson(res, 400, { ok: false, error: "Invalid count." });
        return;
      }
      const url = new URL("/api/v1/commercial/device-licenses/issue", cfg.baseUrl);
      const resp = await commercialJson(url, {
        method: "POST",
        jsonBody: { tenant_key: session.tenantKey, count, ...buildCustomerActorPayload(session) },
      });
      if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
        sendJson(res, 200, { ok: true, ...resp.json, tenant_key: resp.json.tenant_key ?? session.tenantKey });
        return;
      }
      sendJson(res, 502, {
        ok: false,
        error: "Commercial API request failed.",
        details: [`HTTP ${resp.status}`],
        body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
      });
      return;
    }

    if (req.method === "GET" && pathname === "/portal/api/team/invites") {
      const url = new URL("/api/v1/commercial/tenant/invites", cfg.baseUrl);
      url.searchParams.set("tenant_key", session.tenantKey);
      url.searchParams.set("firebase_uid", session.firebaseUID);
      url.searchParams.set("email", session.email);
      url.searchParams.set("role", session.role ?? "");
      const resp = await commercialJson(url, { method: "GET" });
      if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
        sendJson(res, 200, { ok: true, ...resp.json, tenant_key: resp.json.tenant_key ?? session.tenantKey });
        return;
      }
      sendJson(res, 502, {
        ok: false,
        error: "Commercial API request failed.",
        details: [`HTTP ${resp.status}`],
        body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
      });
      return;
    }

    if (req.method === "GET" && pathname === "/portal/api/team/memberships") {
      const url = new URL("/api/v1/commercial/tenant/memberships", cfg.baseUrl);
      url.searchParams.set("tenant_key", session.tenantKey);
      url.searchParams.set("firebase_uid", session.firebaseUID);
      url.searchParams.set("email", session.email);
      url.searchParams.set("role", session.role ?? "");
      const resp = await commercialJson(url, { method: "GET" });
      if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
        sendJson(res, 200, { ok: true, ...resp.json, tenant_key: resp.json.tenant_key ?? session.tenantKey });
        return;
      }
      sendJson(res, 502, {
        ok: false,
        error: "Commercial API request failed.",
        details: [`HTTP ${resp.status}`],
        body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
      });
      return;
    }

    if (req.method === "POST" && pathname === "/portal/api/team/invites/create") {
      if (!csrfOk) {
        sendJson(res, 403, { ok: false, error: "CSRF validation failed." });
        return;
      }
      if (!hasPermission(session, "invite:manage")) {
        sendJson(res, 403, { ok: false, error: "Your role cannot manage team invites." });
        return;
      }
      let body;
      try {
        body = await readJsonBody(req, { maxBytes: 32 * 1024 });
      } catch {
        sendJson(res, 400, { ok: false, error: "Invalid JSON body." });
        return;
      }
      const email = validateEmail(body?.email);
      const role = String(body?.role ?? "").trim().toLowerCase();
      const expiresInHours = Number.parseInt(String(body?.expires_in_hours ?? ""), 10);
      const allowedRoles = new Set(["admin", "operator", "billing", "read_only"]);
      if (!email || !allowedRoles.has(role)) {
        sendJson(res, 400, { ok: false, error: "Invalid invite payload." });
        return;
      }
      const payload = {
        tenant_key: session.tenantKey,
        email,
        role,
        expires_in_hours: Number.isFinite(expiresInHours) && expiresInHours > 0 ? expiresInHours : 120,
        firebase_uid: session.firebaseUID,
        actor_email: session.email,
        actor_role: session.role ?? "",
      };
      const url = new URL("/api/v1/commercial/tenant/invites", cfg.baseUrl);
      const resp = await commercialJson(url, { method: "POST", jsonBody: payload });
      if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
        sendJson(res, 200, { ok: true, ...resp.json, tenant_key: resp.json.tenant_key ?? session.tenantKey });
        return;
      }
      sendJson(res, 502, {
        ok: false,
        error: "Commercial API request failed.",
        details: [`HTTP ${resp.status}`],
        body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
      });
      return;
    }

    const inviteRevokeMatch = pathname.match(/^\/portal\/api\/team\/invites\/([^/]+)\/revoke$/);
    if (req.method === "POST" && inviteRevokeMatch) {
      if (!csrfOk) {
        sendJson(res, 403, { ok: false, error: "CSRF validation failed." });
        return;
      }
      if (!hasPermission(session, "invite:manage")) {
        sendJson(res, 403, { ok: false, error: "Your role cannot manage team invites." });
        return;
      }
      const inviteId = String(inviteRevokeMatch[1] ?? "").trim();
      if (!inviteId) {
        sendJson(res, 400, { ok: false, error: "Invalid invite_id." });
        return;
      }
      const url = new URL(`/api/v1/commercial/tenant/invites/${encodeURIComponent(inviteId)}/revoke`, cfg.baseUrl);
      const resp = await commercialJson(url, {
        method: "POST",
        jsonBody: {
          tenant_key: session.tenantKey,
          invite_id: inviteId,
          firebase_uid: session.firebaseUID,
          actor_email: session.email,
          actor_role: session.role ?? "",
        },
      });
      if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
        sendJson(res, 200, { ok: true, ...resp.json, tenant_key: resp.json.tenant_key ?? session.tenantKey });
        return;
      }
      sendJson(res, 502, {
        ok: false,
        error: "Commercial API request failed.",
        details: [`HTTP ${resp.status}`],
        body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
      });
      return;
    }

    const revokeMatch = pathname.match(/^\/portal\/api\/device-licenses\/([^/]+)\/revoke$/);
    if (req.method === "POST" && revokeMatch) {
      if (!csrfOk) {
        sendJson(res, 403, { ok: false, error: "CSRF validation failed." });
        return;
      }
      if (!hasPermission(session, "device_license:revoke")) {
        sendJson(res, 403, { ok: false, error: "Your role cannot revoke device licenses." });
        return;
      }
      const licenseId = String(revokeMatch[1] ?? "").trim();
      if (!licenseId) {
        sendJson(res, 400, { ok: false, error: "Invalid license_id." });
        return;
      }
      let body;
      try {
        body = await readJsonBody(req, { maxBytes: 32 * 1024 });
      } catch {
        sendJson(res, 400, { ok: false, error: "Invalid JSON body." });
        return;
      }
      const reason = String(body?.reason ?? "").trim().slice(0, 500);
      const url = new URL(`/api/v1/commercial/device-licenses/${encodeURIComponent(licenseId)}/revoke`, cfg.baseUrl);
      const resp = await commercialJson(url, {
        method: "POST",
        jsonBody: { tenant_key: session.tenantKey, reason, ...buildCustomerActorPayload(session) },
      });
      if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
        sendJson(res, 200, { ok: true, ...resp.json, tenant_key: resp.json.tenant_key ?? session.tenantKey });
        return;
      }
      sendJson(res, 502, {
        ok: false,
        error: "Commercial API request failed.",
        details: [`HTTP ${resp.status}`],
        body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
      });
      return;
    }

    sendJson(res, 404, { ok: false, error: "Unknown portal API route." });
    return;
  }
}

async function handleAdminApi(req, res, pathname, session) {
  const adminSession = session ?? loadAdminSession(req);
  if (!adminSession) {
    sendJson(res, 401, { ok: false, error: "Admin sign-in required." });
    return;
  }

  const cookies = parseCookies(req);
  const csrfHeader = String(req.headers["x-csrf-token"] ?? "").trim();
  const csrfCookie = String(cookies[ADMIN_CSRF_COOKIE_NAME] ?? "").trim();
  const adminCsrfOk =
    csrfHeader && csrfCookie && adminSession.csrf && csrfHeader === csrfCookie && csrfHeader === adminSession.csrf;

  if (req.method !== "GET" && req.method !== "HEAD" && !adminCsrfOk) {
    sendJson(res, 403, { ok: false, error: "CSRF validation failed." });
    return;
  }

  const routeRoles = requiredAdminRolesForRoute(pathname);
  if (!routeRoles || !hasAdminRole(adminSession, routeRoles)) {
    sendJson(res, 403, { ok: false, error: "Admin role is not allowed for this route." });
    return;
  }

  if (req.method === "GET" && pathname === "/admin/api/session") {
    const session = loadAdminSession(req);
    sendJson(res, 200, {
      ok: true,
      firebase_uid: session?.firebaseUID ?? "",
      email: session?.email ?? "",
      roles: session?.roles ?? [],
    });
    return;
  }

  const tenantsPath = process.env.AUTOSECOPS_COMMERCIAL_TENANTS_PATH || "/api/v1/commercial/admin/tenants";
  const webhookEventsPath =
    process.env.AUTOSECOPS_COMMERCIAL_WEBHOOK_EVENTS_PATH || "/api/v1/commercial/admin/webhooks/events";
  const webhookReplayPath =
    process.env.AUTOSECOPS_COMMERCIAL_WEBHOOK_REPLAY_PATH || "/api/v1/commercial/admin/webhooks/replay";
  const auditEventsPath = process.env.AUTOSECOPS_COMMERCIAL_AUDIT_EVENTS_PATH || "/api/v1/commercial/admin/audit/events";
  const impersonationStartPath =
    process.env.AUTOSECOPS_COMMERCIAL_IMPERSONATION_START_PATH || "/api/v1/commercial/admin/impersonation/start";
  const impersonationRevokePath =
    process.env.AUTOSECOPS_COMMERCIAL_IMPERSONATION_REVOKE_PATH || "/api/v1/commercial/admin/impersonation/revoke";

  if (req.method === "GET" && pathname === "/admin/api/tenants") {
    const cfg = commercialConfigOrError(res);
    if (!cfg) return;
    const url = new URL(tenantsPath, cfg.baseUrl);

    try {
      const resp = await commercialJson(url, { method: "GET" });
      if (resp.status === 404) {
        sendJson(res, 501, {
          ok: false,
          error: "Commercial tenants endpoint not found.",
          details: [
            "The configured commercial endpoint returned 404.",
            "Update AUTOSECOPS_COMMERCIAL_TENANTS_PATH to the correct path.",
          ],
        });
        return;
      }
      if (resp.status < 200 || resp.status >= 300) {
        sendJson(res, 502, {
          ok: false,
          error: "Commercial API request failed.",
          details: [`HTTP ${resp.status}`],
          body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
        });
        return;
      }

      const tenants = normalizeListPayload(resp.json);
      sendJson(res, 200, { ok: true, tenants, raw: resp.json });
      return;
    } catch (err) {
      sendJson(res, 502, { ok: false, error: "Commercial API request error.", details: [String(err)] });
      return;
    }
  }

  if (req.method === "GET" && pathname === "/admin/api/webhooks/events") {
    const cfg = commercialConfigOrError(res);
    if (!cfg) return;
    const url = new URL(webhookEventsPath, cfg.baseUrl);

    try {
      const resp = await commercialJson(url, { method: "GET" });
      if (resp.status === 404) {
        sendJson(res, 501, {
          ok: false,
          error: "Commercial webhook events endpoint not found.",
          details: [
            "The configured commercial endpoint returned 404.",
            "Update AUTOSECOPS_COMMERCIAL_WEBHOOK_EVENTS_PATH to the correct path.",
          ],
        });
        return;
      }
      if (resp.status < 200 || resp.status >= 300) {
        sendJson(res, 502, {
          ok: false,
          error: "Commercial API request failed.",
          details: [`HTTP ${resp.status}`],
          body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
        });
        return;
      }

      const events = normalizeListPayload(resp.json);
      sendJson(res, 200, { ok: true, events, raw: resp.json });
      return;
    } catch (err) {
      sendJson(res, 502, { ok: false, error: "Commercial API request error.", details: [String(err)] });
      return;
    }
  }

  if (req.method === "POST" && pathname === "/admin/api/webhooks/replay") {
    const cfg = commercialConfigOrError(res);
    if (!cfg) return;

    let body = null;
    try {
      body = await readJsonBody(req);
    } catch (err) {
      if (err?.code === "PAYLOAD_TOO_LARGE") {
        sendJson(res, 413, { ok: false, error: "Payload too large." });
        return;
      }
      sendJson(res, 400, { ok: false, error: "Invalid JSON body." });
      return;
    }

    const url = new URL(webhookReplayPath, cfg.baseUrl);

    try {
      const resp = await commercialJson(url, {
        method: "POST",
        jsonBody: { ...(body ?? {}), ...buildAdminActorPayload(adminSession) },
      });
      if (resp.status === 404) {
        sendJson(res, 501, {
          ok: false,
          error: "Commercial webhook replay endpoint not found.",
          details: [
            "The configured commercial endpoint returned 404.",
            "Update AUTOSECOPS_COMMERCIAL_WEBHOOK_REPLAY_PATH to the correct path.",
          ],
        });
        return;
      }
      if (resp.status < 200 || resp.status >= 300) {
        sendJson(res, 502, {
          ok: false,
          error: "Commercial API request failed.",
          details: [`HTTP ${resp.status}`],
          body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
        });
        return;
      }

      sendJson(res, 200, { ok: true, result: resp.json ?? resp.bodyText });
      return;
    } catch (err) {
      sendJson(res, 502, { ok: false, error: "Commercial API request error.", details: [String(err)] });
      return;
    }
  }

  if (req.method === "POST" && pathname === "/admin/api/impersonation/start") {
    const cfg = commercialConfigOrError(res);
    if (!cfg) return;
    let body = null;
    try {
      body = await readJsonBody(req);
    } catch (err) {
      if (err?.code === "PAYLOAD_TOO_LARGE") {
        sendJson(res, 413, { ok: false, error: "Payload too large." });
        return;
      }
      sendJson(res, 400, { ok: false, error: "Invalid JSON body." });
      return;
    }
    const url = new URL(impersonationStartPath, cfg.baseUrl);
    const resp = await commercialJson(url, {
      method: "POST",
      jsonBody: { ...(body ?? {}), ...buildAdminActorPayload(adminSession) },
    });
    if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
      sendJson(res, 200, { ok: true, result: resp.json });
      return;
    }
    sendJson(res, 502, {
      ok: false,
      error: "Commercial API request failed.",
      details: [`HTTP ${resp.status}`],
      body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
    });
    return;
  }

  if (req.method === "POST" && pathname === "/admin/api/impersonation/revoke") {
    const cfg = commercialConfigOrError(res);
    if (!cfg) return;
    let body = null;
    try {
      body = await readJsonBody(req);
    } catch (err) {
      if (err?.code === "PAYLOAD_TOO_LARGE") {
        sendJson(res, 413, { ok: false, error: "Payload too large." });
        return;
      }
      sendJson(res, 400, { ok: false, error: "Invalid JSON body." });
      return;
    }
    const url = new URL(impersonationRevokePath, cfg.baseUrl);
    const resp = await commercialJson(url, {
      method: "POST",
      jsonBody: { ...(body ?? {}), ...buildAdminActorPayload(adminSession) },
    });
    if (resp.status >= 200 && resp.status < 300 && resp.json && typeof resp.json === "object") {
      sendJson(res, 200, { ok: true, result: resp.json });
      return;
    }
    sendJson(res, 502, {
      ok: false,
      error: "Commercial API request failed.",
      details: [`HTTP ${resp.status}`],
      body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
    });
    return;
  }

  if (req.method === "GET" && pathname === "/admin/api/audit/events") {
    const cfg = commercialConfigOrError(res);
    if (!cfg) return;
    const url = new URL(auditEventsPath, cfg.baseUrl);

    try {
      const resp = await commercialJson(url, { method: "GET" });
      if (resp.status === 404) {
        sendJson(res, 501, {
          ok: false,
          error: "Commercial audit events endpoint not found.",
          details: [
            "The configured commercial endpoint returned 404.",
            "If audit events are required, a commercial API endpoint must exist (do not add this to AutoSecOps OSS).",
          ],
        });
        return;
      }
      if (resp.status < 200 || resp.status >= 300) {
        sendJson(res, 502, {
          ok: false,
          error: "Commercial API request failed.",
          details: [`HTTP ${resp.status}`],
          body: typeof resp.json === "object" ? resp.json : resp.bodyText?.slice(0, 2000),
        });
        return;
      }

      const events = normalizeListPayload(resp.json);
      sendJson(res, 200, { ok: true, events, raw: resp.json });
      return;
    } catch (err) {
      sendJson(res, 502, { ok: false, error: "Commercial API request error.", details: [String(err)] });
      return;
    }
  }

  sendJson(res, 404, { ok: false, error: "Unknown admin API route." });
}

validateStartupConfigOrThrow();

const server = http.createServer(async (req, res) => {
  try {
    const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? `${HOST}:${PORT}`}`);
    const pathname = requestUrl.pathname;

    if (ENFORCE_HTTPS && !isSecureRequest(req)) {
      const host = String(req.headers.host ?? "").trim();
      const redirectBase = PUBLIC_BASE_URL && PUBLIC_BASE_URL.startsWith("https://") ? PUBLIC_BASE_URL : host ? `https://${host}` : null;
      if (!redirectBase) {
        sendJson(res, 503, { ok: false, error: "HTTPS enforcement is enabled but redirect base is not configured." });
        return;
      }
      setCommonSecurityHeaders(res);
      res.writeHead(308, { Location: `${redirectBase}${pathname}${requestUrl.search}`, "Cache-Control": "no-store" });
      res.end();
      return;
    }

    if (pathname.startsWith("/.git") || pathname.startsWith("/.env")) {
      setCommonSecurityHeaders(res);
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found.");
      return;
    }

    if (pathname.startsWith("/auth/")) {
      if (await handleAuth(req, res, pathname)) return;
    }

    if (pathname === "/portal") {
      setCommonSecurityHeaders(res);
      res.writeHead(303, { Location: "/portal/", "Cache-Control": "no-store" });
      res.end();
      return;
    }

    if (pathname === "/portal/start" || pathname.startsWith("/portal/")) {
      await handlePortal(req, res, pathname);
      if (res.headersSent) return;

      const fsPath = resolveSafePath(pathname === "/portal/" ? "/portal/index.html" : pathname);
      if (!fsPath) {
        setCommonSecurityHeaders(res);
        res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Bad path.");
        return;
      }

      const cacheControl = pathname.startsWith("/portal/_assets/") ? "public, max-age=300" : "no-store";
      await serveFile(req, res, fsPath, { cacheControl });
      return;
    }

    if (pathname === "/admin" || pathname.startsWith("/admin/")) {
      if (await handleAdminAuth(req, res, pathname)) return;

      if (req.method === "POST" && pathname === "/admin/logout") {
        clearAdminSession(req, res);
        res.writeHead(303, { Location: "/admin/login/", "Cache-Control": "no-store" });
        res.end();
      return;
    }

    const adminSession = loadAdminSession(req);
    if (adminSession && !isAdminAllowlisted(adminSession.email)) {
      clearAdminSession(req, res);
      if (pathname.startsWith("/admin/api/")) {
        sendJson(res, 401, { ok: false, error: "Admin sign-in required." });
      } else {
        res.writeHead(303, { Location: "/admin/login/", "Cache-Control": "no-store" });
        res.end();
      }
      return;
    }

    let allowBasicFallback = false;
    if (!adminSession && adminBasicAuthFallbackAllowed()) {
      allowBasicFallback = requireBasicAuth(req, res);
      if (!allowBasicFallback && res.headersSent) return;
    }
      const isLoginAsset = pathname === "/admin/login" || pathname.startsWith("/admin/login/") || pathname.startsWith("/admin/_assets/");
      if (!adminSession && !allowBasicFallback && !isLoginAsset) {
        res.writeHead(303, { Location: "/admin/login/", "Cache-Control": "no-store" });
        res.end();
        return;
      }

      if (pathname.startsWith("/admin/api/")) {
        if (!adminSession && !allowBasicFallback) {
          sendJson(res, 401, { ok: false, error: "Admin sign-in required." });
          return;
        }
        setCommonSecurityHeaders(res);
        await handleAdminApi(req, res, pathname, adminSession);
        return;
      }

      const fsPath = resolveSafePath(pathname);
      if (!fsPath) {
        setCommonSecurityHeaders(res);
        res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Bad path.");
        return;
      }

      await serveFile(req, res, fsPath, { cacheControl: "no-store" });
      return;
    }

    const fsPath = resolveSafePath(pathname === "/" ? "/index.html" : pathname);
    if (!fsPath) {
      setCommonSecurityHeaders(res);
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Bad path.");
      return;
    }

    await serveFile(req, res, fsPath, { cacheControl: "public, max-age=300" });
  } catch (err) {
    setCommonSecurityHeaders(res);
    sendJson(res, 500, { ok: false, error: "Internal server error.", details: [String(err)] });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`silanding server listening on http://${HOST}:${PORT}`);
});
