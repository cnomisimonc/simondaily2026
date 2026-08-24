/**
 * Simon's Daily — access gate for simondaily2026.pages.dev
 *
 * Runs in front of EVERY request as a Cloudflare Pages Function.
 * A visitor must supply an allowed email address AND the shared site
 * password. On success they receive a signed, HttpOnly session cookie
 * that lasts 30 days. No Cloudflare Access, no emailed PIN codes.
 *
 * Configure these in the Cloudflare dashboard:
 *   Workers & Pages -> simondaily2026 -> Settings -> Variables and secrets
 * Add them to BOTH the Production and Preview environments.
 * Never commit their values to this repo.
 *
 *   SITE_PASSWORD   the shared password everyone types
 *   ALLOWED_EMAILS  comma- or newline-separated list of permitted addresses.
 *                   A bare "@example.com" entry allows every address at
 *                   that domain.
 *   AUTH_SECRET     a long random string used to sign the session cookie.
 *                   Changing it immediately signs everybody out.
 */

const COOKIE = "sd_session";
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days
const LOGIN_PATH = "/__auth/login";
const LOGOUT_PATH = "/__auth/logout";
const enc = new TextEncoder();

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  const secret = env.AUTH_SECRET;
  const password = env.SITE_PASSWORD;
  const allowed = parseAllowed(env.ALLOWED_EMAILS);

  // Fail closed if the gate has not been configured yet.
  if (!secret || !password || allowed.length === 0) {
    return html(setupPage(), 503);
  }

  if (url.pathname === LOGOUT_PATH) {
    const res = redirect("/");
    res.headers.append("Set-Cookie", expiredCookie());
    return res;
  }

  if (url.pathname === LOGIN_PATH && request.method === "POST") {
    let form;
    try {
      form = await request.formData();
    } catch {
      return html(loginPage("Could not read that form. Please try again."), 400);
    }

    const email = String(form.get("email") || "").trim().toLowerCase();
    const pass = String(form.get("password") || "");
    const dest = safeNext(form.get("next"));

    const okEmail = isAllowed(email, allowed);
    const okPass = await secretsMatch(pass, password);

    if (!okEmail || !okPass) {
      // Deliberately vague, and slowed down, to frustrate guessing.
      await sleep(600);
      return html(loginPage("That email or password was not accepted.", dest), 401);
    }

    const token = await makeToken(email, secret);
    const res = redirect(dest);
    res.headers.append(
      "Set-Cookie",
      `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`
    );
    return res;
  }

  const email = await verifyToken(readCookie(request, COOKIE), secret);
  if (email && isAllowed(email, allowed)) {
    return next();
  }

  const res = html(loginPage(null, url.pathname + url.search), 401);
  // A stale or tampered cookie should not linger.
  if (readCookie(request, COOKIE)) res.headers.append("Set-Cookie", expiredCookie());
  return res;
}

/* ---------------------------------------------------------------- helpers */

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseAllowed(raw) {
  return String(raw || "")
    .split(/[\s,;]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function isAllowed(email, allowed) {
  if (!email || !email.includes("@")) return false;
  const domain = email.slice(email.lastIndexOf("@"));
  return allowed.some((a) => (a.startsWith("@") ? a === domain : a === email));
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

function expiredCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

// Only ever redirect to a same-origin path, never to an absolute URL.
function safeNext(value) {
  const v = String(value || "/");
  if (!v.startsWith("/") || v.startsWith("//")) return "/";
  if (v.startsWith(LOGIN_PATH) || v.startsWith(LOGOUT_PATH)) return "/";
  return v;
}

function redirect(location) {
  return new Response(null, {
    status: 303,
    headers: { Location: location, "Cache-Control": "no-store" },
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function b64url(buf) {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s) {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/");
  return atob(pad + "=".repeat((4 - (pad.length % 4)) % 4));
}

// Equal-length, branch-free string comparison.
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Hash both sides first so the comparison never leaks the password length.
async function secretsMatch(a, b) {
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  return timingSafeEqual(ha, hb);
}

async function sha256(value) {
  return b64url(await crypto.subtle.digest("SHA-256", enc.encode(value)));
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return b64url(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}

async function makeToken(email, secret) {
  const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
  const payload = b64url(enc.encode(`${email}|${exp}`));
  return `${payload}.${await hmac(payload, secret)}`;
}

async function verifyToken(token, secret) {
  if (!token || token.indexOf(".") === -1) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  if (!timingSafeEqual(sig, await hmac(payload, secret))) return null;

  let decoded;
  try {
    decoded = fromB64url(payload);
  } catch {
    return null;
  }

  const sep = decoded.lastIndexOf("|");
  if (sep === -1) return null;
  const email = decoded.slice(0, sep);
  const exp = Number(decoded.slice(sep + 1));
  if (!email || !Number.isFinite(exp)) return null;
  if (exp < Math.floor(Date.now() / 1000)) return null;
  return email;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

/* ------------------------------------------------------------------ pages */

const SHELL = (title, inner) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${title}</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;
    background:#0e1116;color:#e8eaed;
    font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
  .card{width:min(92vw,380px);background:#161b22;border:1px solid #2b323c;
    border-radius:14px;padding:32px 30px;box-shadow:0 18px 50px rgba(0,0,0,.45)}
  h1{margin:0 0 4px;font-size:20px;letter-spacing:-.01em}
  .sub{margin:0 0 22px;color:#9aa4b2;font-size:13.5px}
  label{display:block;margin:0 0 6px;font-size:12.5px;color:#9aa4b2;
    text-transform:uppercase;letter-spacing:.06em}
  input{width:100%;padding:11px 12px;margin-bottom:16px;border-radius:8px;
    border:1px solid #2b323c;background:#0e1116;color:#e8eaed;font-size:15px}
  input:focus{outline:none;border-color:#c9a227;box-shadow:0 0 0 3px rgba(201,162,39,.15)}
  button{width:100%;padding:11px;border:0;border-radius:8px;background:#c9a227;
    color:#14171c;font-size:15px;font-weight:600;cursor:pointer}
  button:hover{background:#dcb32c}
  .err{margin:0 0 16px;padding:10px 12px;border-radius:8px;font-size:13.5px;
    background:rgba(220,80,80,.12);border:1px solid rgba(220,80,80,.35);color:#ff9c9c}
  .foot{margin:18px 0 0;font-size:12px;color:#6b7480;text-align:center}
  code{background:#0e1116;border:1px solid #2b323c;border-radius:4px;padding:1px 5px;font-size:12.5px}
  ul{margin:10px 0 0;padding-left:20px;color:#9aa4b2;font-size:13.5px}
  li{margin-bottom:6px}
</style></head>
<body><main class="card">${inner}</main></body></html>`;

function loginPage(error, dest = "/") {
  return SHELL(
    "Sign in — Simon's Daily",
    `<h1>Simon's Daily</h1>
     <p class="sub">Private dashboard. Please sign in.</p>
     ${error ? `<p class="err">${escapeHtml(error)}</p>` : ""}
     <form method="POST" action="${LOGIN_PATH}" autocomplete="on">
       <input type="hidden" name="next" value="${escapeHtml(dest)}">
       <label for="email">Email</label>
       <input id="email" name="email" type="email" required autofocus
              autocomplete="username" placeholder="you@example.com">
       <label for="password">Password</label>
       <input id="password" name="password" type="password" required
              autocomplete="current-password" placeholder="••••••••••">
       <button type="submit">Sign in</button>
     </form>
     <p class="foot">Heyokha Brothers</p>`
  );
}

function setupPage() {
  return SHELL(
    "Setup required — Simon's Daily",
    `<h1>Setup required</h1>
     <p class="sub">The access gate is deployed but not yet configured, so the
     site is closed to everyone.</p>
     <p style="font-size:13.5px;color:#9aa4b2;margin:0">Add these in Cloudflare →
     Workers &amp; Pages → <code>simondaily2026</code> → Settings → Variables and
     secrets, for both Production and Preview:</p>
     <ul>
       <li><code>SITE_PASSWORD</code> — the shared password</li>
       <li><code>ALLOWED_EMAILS</code> — comma-separated addresses</li>
       <li><code>AUTH_SECRET</code> — a long random string</li>
     </ul>
     <p class="foot">Redeploy after saving.</p>`
  );
}
