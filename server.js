/**
 * Subaccounts mock API server
 * Implements the endpoints from "Subaccounts - Design Document v1.0" with real,
 * in-memory state: creates persist, PATCH actually changes fields, login codes
 * are single-use and expire, revoke cascades to codes/logins, changing a
 * terminal invalidates the existing login.
 *
 * Run:   node server.js
 * Port:  process.env.PORT || 3000
 */

const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// ---------------------------------------------------------------------------
// In-memory "database"
// ---------------------------------------------------------------------------

let nextSubaccountId = 42; // arbitrary starting point, matches the doc's example
const subaccounts = new Map(); // id -> subaccount object

// loginCodes: subaccountId -> { code, expiresAt (ms epoch), used }
const loginCodes = new Map();
// codeIndex: code (string) -> subaccountId, for O(1) lookup at /api/token/subaccount/
const codeIndex = new Map();

// logins: subaccountId -> { access, refresh, terminalAtIssue }
const logins = new Map();
// tokenIndex: access/refresh token string -> subaccountId
const accessIndex = new Map();
const refreshIndex = new Map();

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nowIso() {
  return new Date().toISOString();
}

function randomToken(prefix) {
  return `${prefix}.${crypto.randomBytes(24).toString("hex")}`;
}

function randomEightDigitCode() {
  // zero-padded, so "04728163" stays a string with leading zeroes preserved
  const n = crypto.randomInt(0, 100000000);
  return n.toString().padStart(8, "0");
}

// Deterministic, always-valid fake merchant lookup for a terminal id.
// Real backend would look this up from the terminal's actual merchant;
// here we just need *something* stable so re-reading a subaccount is consistent.
function merchantForTerminal(terminalId) {
  return 1000 + (terminalId % 1000);
}

function serializeSubaccount(s) {
  return {
    id: s.id,
    Name: s.Name,
    Terminal: s.Terminal,
    Merchant: s.Merchant,
    IsActive: s.IsActive,
    CreatedAt: s.CreatedAt,
  };
}

function requireAuth(req, res) {
  const authHeader = req.header("Authorization") || "";
  if (!authHeader.startsWith("Bearer ") || authHeader.length <= 7) {
    res.status(401).json({ status: "unauthorized" });
    return null;
  }
  // Mock: we don't validate the real JWT, we just require *a* bearer
  // token, since subaccount management is always called as the normal user.
  return authHeader.slice(7);
}

function findSubaccountOr404(req, res) {
  const id = parseInt(req.params.id, 10);
  const sub = subaccounts.get(id);
  if (!sub) {
    res.status(404).json({ detail: "Not found." });
    return null;
  }
  return sub;
}

function invalidateLogin(subaccountId) {
  const existing = logins.get(subaccountId);
  if (existing) {
    accessIndex.delete(existing.access);
    refreshIndex.delete(existing.refresh);
    logins.delete(subaccountId);
  }
}

function invalidateLoginCode(subaccountId) {
  const existing = loginCodes.get(subaccountId);
  if (existing) {
    codeIndex.delete(existing.code);
    loginCodes.delete(subaccountId);
  }
}

// ---------------------------------------------------------------------------
// Request logging (handy while wiring up the Android client)
// ---------------------------------------------------------------------------

app.use((req, res, next) => {
  log(`${req.method} ${req.originalUrl}`, Object.keys(req.body || {}).length ? req.body : "");
  next();
});

// ---------------------------------------------------------------------------
// 5.1 List Subaccounts
// ---------------------------------------------------------------------------

app.get("/api/v2.2/subaccount/", (req, res) => {
  if (!requireAuth(req, res)) return;
  const results = Array.from(subaccounts.values()).map(serializeSubaccount);
  res.status(200).json({
    count: results.length,
    next: null,
    previous: null,
    results,
  });
});

// ---------------------------------------------------------------------------
// 5.2 Create Subaccount
// ---------------------------------------------------------------------------

app.post("/api/v2.2/subaccount/", (req, res) => {
  if (!requireAuth(req, res)) return;

  const { Name, Terminal } = req.body || {};

  if (!Name || typeof Name !== "string" || !Name.trim()) {
    return res.status(400).json({ Name: ["This field is required."] });
  }
  if (Terminal === undefined || Terminal === null || !Number.isInteger(Terminal)) {
    return res.status(400).json({ Terminal: ["This field is required."] });
  }
  if (Terminal <= 0) {
    return res.status(400).json({ status: "invalid_terminal" });
  }

  const id = nextSubaccountId++;
  const sub = {
    id,
    Name,
    Terminal,
    Merchant: merchantForTerminal(Terminal),
    IsActive: true,
    CreatedAt: nowIso(),
  };
  subaccounts.set(id, sub);

  res.status(201).json(serializeSubaccount(sub));
});

// ---------------------------------------------------------------------------
// 5.3 Retrieve Subaccount (in the doc's ToC, not wired in the Java client yet,
// included here for completeness / future use)
// ---------------------------------------------------------------------------

app.get("/api/v2.2/subaccount/:id/", (req, res) => {
  if (!requireAuth(req, res)) return;
  const sub = findSubaccountOr404(req, res);
  if (!sub) return;
  res.status(200).json(serializeSubaccount(sub));
});

// ---------------------------------------------------------------------------
// 5.4 Update Subaccount
// ---------------------------------------------------------------------------

app.patch("/api/v2.2/subaccount/:id/", (req, res) => {
  if (!requireAuth(req, res)) return;
  const sub = findSubaccountOr404(req, res);
  if (!sub) return;

  const { Name, Terminal } = req.body || {};

  if (Name !== undefined) {
    if (typeof Name !== "string" || !Name.trim()) {
      return res.status(400).json({ Name: ["This field may not be blank."] });
    }
    sub.Name = Name;
  }

  if (Terminal !== undefined) {
    if (!Number.isInteger(Terminal) || Terminal <= 0) {
      return res.status(400).json({ status: "invalid_terminal" });
    }
    if (Terminal !== sub.Terminal) {
      sub.Terminal = Terminal;
      sub.Merchant = merchantForTerminal(Terminal);
      // "Changing the terminal ends the existing subaccount login."
      invalidateLogin(sub.id);
      invalidateLoginCode(sub.id);
    }
  }

  res.status(200).json(serializeSubaccount(sub));
});

// ---------------------------------------------------------------------------
// 5.5 Generate Login Code
// ---------------------------------------------------------------------------

app.post("/api/v2.2/subaccount/:id/logincode/", (req, res) => {
  if (!requireAuth(req, res)) return;
  const sub = findSubaccountOr404(req, res);
  if (!sub) return;

  let validitySeconds = 300;
  if (req.body && req.body.ValiditySeconds !== undefined) {
    const v = req.body.ValiditySeconds;
    if (!Number.isInteger(v) || v < 60 || v > 300) {
      return res.status(400).json({ ValiditySeconds: ["Must be between 60 and 300."] });
    }
    validitySeconds = v;
  }

  // "Any previously generated, unused code for the same subaccount becomes invalid."
  invalidateLoginCode(sub.id);

  const code = randomEightDigitCode();
  const expiresAt = Date.now() + validitySeconds * 1000;

  loginCodes.set(sub.id, { code, expiresAt, used: false });
  codeIndex.set(code, sub.id);

  res.status(200).json({
    status: "success",
    Code: code,
    QrPayload: `subaccount-login:${code}`,
    ExpiresAt: new Date(expiresAt).toISOString(),
  });
});

// ---------------------------------------------------------------------------
// 5.6 Revoke Subaccount
// ---------------------------------------------------------------------------

app.post("/api/v2.2/subaccount/:id/revoke/", (req, res) => {
  if (!requireAuth(req, res)) return;
  const id = parseInt(req.params.id, 10);
  const sub = subaccounts.get(id);

  if (sub) {
    sub.IsActive = false;
    invalidateLoginCode(id);
    invalidateLogin(id);
  }
  // "Repeating the request for an already revoked subaccount returns the
  // same successful response." We extend that to "even if already deleted".
  res.status(200).json({ status: "success" });
});

// ---------------------------------------------------------------------------
// 5.7 Subaccount Login
// ---------------------------------------------------------------------------

app.post("/api/token/subaccount/", (req, res) => {
  const code = req.body && req.body.Code;

  if (typeof code !== "string" || !/^\d{8}$/.test(code)) {
    return res.status(400).json({ status: "invalid_login_code" });
  }

  const subaccountId = codeIndex.get(code);
  const entry = subaccountId !== undefined ? loginCodes.get(subaccountId) : null;
  const sub = subaccountId !== undefined ? subaccounts.get(subaccountId) : null;

  const invalid =
    !entry ||
    !sub ||
    !sub.IsActive ||
    entry.used ||
    entry.code !== code ||
    Date.now() > entry.expiresAt;

  if (invalid) {
    return res.status(401).json({ status: "invalid_login_code" });
  }

  // single-use
  entry.used = true;
  codeIndex.delete(code);

  const access = randomToken("access");
  const refresh = randomToken("refresh");
  logins.set(sub.id, { access, refresh, terminalAtIssue: sub.Terminal });
  accessIndex.set(access, sub.id);
  refreshIndex.set(refresh, sub.id);

  res.status(200).json({ access, refresh });
});

// ---------------------------------------------------------------------------
// 5.8 Refresh Access Token (shared with normal-user flow in the real backend;
// here it only knows about subaccount refresh tokens)
// ---------------------------------------------------------------------------

app.post("/api/token/refresh/", (req, res) => {
  const refresh = req.body && req.body.refresh;
  const subaccountId = refresh ? refreshIndex.get(refresh) : undefined;
  const sub = subaccountId !== undefined ? subaccounts.get(subaccountId) : null;
  const login = subaccountId !== undefined ? logins.get(subaccountId) : null;

  const invalid =
    !sub ||
    !login ||
    login.refresh !== refresh ||
    !sub.IsActive ||
    login.terminalAtIssue !== sub.Terminal;

  if (invalid) {
    return res.status(401).json({ status: "unauthorized" });
  }

  const access = randomToken("access");
  accessIndex.delete(login.access);
  login.access = access;
  accessIndex.set(access, sub.id);

  res.status(200).json({ access });
});

// ---------------------------------------------------------------------------
// Fallback error handler
// ---------------------------------------------------------------------------

app.use((req, res) => {
  res.status(404).json({ detail: "Not found." });
});

app.use((err, req, res, next) => {
  log("Unexpected error", err);
  res.status(500).json({ detail: "Internal server error." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log(`Subaccounts mock API listening on port ${PORT}`);
});
