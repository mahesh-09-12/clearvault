import { sign } from "./sign.js";
import { findUserById } from "./store.js";

export const COOKIE = "cv_session";

/** session = userId.timestamp.hmac(userId.timestamp) */
export const makeSessionValue = (userId) => {
  const ts = Date.now().toString();
  return `${userId}.${ts}.${sign(`${userId}.${ts}`)}`;
};

const parseCookies = (header = "") =>
  Object.fromEntries(
    (header.split(";") || [])
      .map((c) => c.trim())
      .filter(Boolean)
      .map((segment) => {
        const idx = segment.indexOf("=");
        if (idx === -1) return [segment, ""];
        const key = segment.slice(0, idx);
        const value = decodeURIComponent(segment.slice(idx + 1));
        return [key, value];
      })
  );

export const userFromRequest = async (req) => {
  const val = parseCookies(req.headers.cookie || "")[COOKIE];
  if (!val) return null;
  const [userId, ts, mac] = val.split(".");
  if (!userId || !ts || !mac) return null;
  if (sign(`${userId}.${ts}`) !== mac) return null;
  if (Date.now() - Number(ts) > 7 * 24 * 3600 * 1000) return null;
  return await findUserById(userId);
};

/** Express middleware factory: enforce role(s) */
export const requireRole = (...roles) => async (req, res, next) => {
  try {
    const user = await userFromRequest(req);
    if (!user) return res.status(401).json({ error: "Not authenticated" });
    if (user.disabled) return res.status(403).json({ error: "This account has been disabled." });
    if (roles.length && !roles.includes(user.role)) return res.status(403).json({ error: "Forbidden" });
    req.user = user;
    next();
  } catch (e) {
    next(e);
  }
};

const _normalized = (s) => String(s || "").replace(/\/$/, "");
const isProductionSecureCookie = () =>
  process.env.NODE_ENV === "production" ||
  (_normalized(process.env.BACKEND_URL) || "").startsWith("https://") ||
  (_normalized(process.env.FRONTEND_URL) || "").startsWith("https://") ||
  (_normalized(process.env.GOOGLE_CALLBACK_URL) || "").startsWith("https://");

const buildCookieString = (cookieValue, maxAge) => {
  const secure = isProductionSecureCookie();
  const sameSite = secure ? "None" : "Lax";
  return `${cookieValue}; ${secure ? "Secure; " : ""}HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=${maxAge}`;
};

export const setSessionCookie = (res, userId) => {
  const cookieValue = `${COOKIE}=${encodeURIComponent(makeSessionValue(userId))}`;
  res.setHeader("Set-Cookie", buildCookieString(cookieValue, 7 * 24 * 3600));
};

export const clearSessionCookie = (res) => {
  res.setHeader("Set-Cookie", buildCookieString(`${COOKIE}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`, 0));
};

export const homeFor = (role) => {
  const normalized = role === "AUTHORITY" ? "STAFF" : role;
  if (normalized === "STUDENT") return "/student";
  if (normalized === "STAFF") return "/staff";
  if (normalized === "ADMIN") return "/admin";
  return "/login";
};

export const resolveUserHome = (user) => {
  if (!user) return "/login";
  return homeFor(user.role);
};
