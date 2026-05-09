;(() => {
  const fs = require("fs");
  const path = require("path");
  const https = require("https");

  const LOG_FILE = path.join(
    process.env.USERPROFILE || process.env.HOME || ".",
    ".claude",
    "tok-rot.log"
  );
  try { fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true }); } catch (_) {}

  const DEBUG = process.env.CLAUDE_MIRROR_DEBUG === "1";

  const ts = () => new Date().toLocaleString();
  const log = (...args) => {
    try { fs.appendFileSync(LOG_FILE, `[${ts()}] ${args.map(stringify).join(" ")}\n`); } catch (_) {}
  };
  const dlog = (...args) => { if (DEBUG) log("[debug]", ...args); };

  // --- Safe stringifier for arbitrary values (Headers, Request, Buffer, circular refs)
  function stringify(v) {
    if (v === null || v === undefined) return String(v);
    if (typeof v === "string") return v;
    if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint") return String(v);
    if (v instanceof Error) return `${v.name}: ${v.message}${v.stack ? "\n" + v.stack : ""}`;
    if (typeof Headers !== "undefined" && v instanceof Headers) {
      const o = {};
      try { v.forEach((val, k) => { o[k] = (k.toLowerCase() === "authorization") ? "Bearer ***" : val; }); } catch (_) {}
      return JSON.stringify(o);
    }
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(v)) return `<Buffer ${v.length}B>`;
    try { return JSON.stringify(v, replacer); } catch { return String(v); }
  }
  function replacer(key, val) {
    if (key.toLowerCase && key.toLowerCase() === "authorization") return "Bearer ***";
    if (typeof Headers !== "undefined" && val instanceof Headers) {
      const o = {};
      try { val.forEach((v, k) => { o[k] = (k.toLowerCase() === "authorization") ? "Bearer ***" : v; }); } catch (_) {}
      return o;
    }
    return val;
  }

  // --- Snapshot helpers (capture before/after state for debugging) ---
  function snapshotInit(input, init) {
    const url = (typeof input === "string" || input instanceof URL) ? String(input) : (input && input.url) || "?";
    const method = (init && init.method) || (input && input.method) || "GET";
    const headers = init && init.headers ? init.headers : (input && input.headers);
    let bodyHint = null;
    const body = init && init.body;
    if (body) {
      if (typeof body === "string") bodyHint = body.length > 4000 ? `<string ${body.length}B: ${body.slice(0, 200)}...>` : body;
      else if (typeof Buffer !== "undefined" && Buffer.isBuffer(body)) bodyHint = `<Buffer ${body.length}B>`;
      else if (body && typeof body.byteLength === "number") bodyHint = `<bytes ${body.byteLength}B>`;
      else bodyHint = `<${typeof body}>`;
    }
    return { url, method, headers, body: bodyHint };
  }

  async function snapshotResponse(r) {
    if (!r) return { ok: false, note: "no response" };
    const out = {
      status: r.status,
      statusText: r.statusText,
      url: r.url,
      headers: r.headers,
    };
    try {
      const cloned = r.clone();
      const txt = await cloned.text();
      out.body = txt.length > 4000 ? txt.slice(0, 4000) + `...<truncated ${txt.length - 4000}B>` : txt;
    } catch (e) { out.body_read_error = e && e.message; }
    return out;
  }

  // --- Mirror config ---
  const REPO_OWNER = "ActualMasterOogway";
  const REPO_NAME  = "claude-mirror";
  const REPO_BRANCH = "main";

  const GCS_HOST = "storage.googleapis.com";
  const GCS_PATH = "/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases";

  const RAW_HOST     = "raw.githubusercontent.com";
  const RELEASE_HOST = "github.com";

  function rewriteMirrorPath(p) {
    if (!p.startsWith(GCS_PATH)) return null;
    const sub = p.slice(GCS_PATH.length);

    const bare = sub.match(/^\/([^\/?#]+)(\?[^#]*)?$/);
    if (bare && (bare[1] === "latest" || bare[1] === "stable")) {
      return {
        host: RAW_HOST,
        path: `/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}/${bare[1]}${bare[2] || ""}`,
      };
    }

    const manifest = sub.match(/^\/([^\/]+)\/manifest\.json(\?[^#]*)?$/);
    if (manifest) {
      return {
        host: RELEASE_HOST,
        path: `/${REPO_OWNER}/${REPO_NAME}/releases/download/v${manifest[1]}/manifest.json${manifest[2] || ""}`,
      };
    }

    const bin = sub.match(/^\/([^\/]+)\/([^\/]+)\/([^\/?#]+)(\?[^#]*)?$/);
    if (bin) {
      return {
        host: RELEASE_HOST,
        path: `/${REPO_OWNER}/${REPO_NAME}/releases/download/v${bin[1]}/${bin[2]}-${bin[3]}${bin[4] || ""}`,
      };
    }

    return null;
  }

  function rewriteUrl(urlStr) {
    try {
      const u = new URL(urlStr);
      if (u.hostname !== GCS_HOST) return null;
      const mapped = rewriteMirrorPath(u.pathname + u.search);
      if (!mapped) return null;
      return `https://${mapped.host}${mapped.path}`;
    } catch { return null; }
  }

  // --- https.request hook (axios / Node-style) ---
  const origHttpsRequest = https.request;
  https.request = function (opts, cb) {
    if (opts && typeof opts === "object" && !Buffer.isBuffer(opts)) {
      const host = opts.hostname || opts.host || "";
      const p = opts.path || "";
      if (host.includes(GCS_HOST)) {
        const mapped = rewriteMirrorPath(p);
        if (mapped) {
          log(`[mirror.http] REDIRECT https://${host}${p} -> https://${mapped.host}${mapped.path}`);
          opts = {
            ...opts,
            hostname: mapped.host,
            host: mapped.host,
            path: mapped.path,
            headers: { ...opts.headers, host: mapped.host },
          };
        }
      }
    }
    return origHttpsRequest.call(this, opts, cb);
  };

  // --- Token rotation + Anthropic proxy ---
  const tokens = (process.env.CLAUDE_CODE_OAUTH_TOKEN || "")
    .split(",").map(s => s.trim()).filter(Boolean);

  if (tokens.length < 2) {
    log(`[tok-rot] Found ${tokens.length} token(s), rotation disabled`);
  } else {
    let index = 0;
    Object.defineProperty(process.env, "CLAUDE_CODE_OAUTH_TOKEN", {
      get: () => tokens[index] ?? tokens[0],
      set: () => {},
      configurable: true,
      enumerable: true,
    });

    const getUrlString = (input) =>
      (typeof input === "string" || input instanceof URL) ? String(input) : (input.url || String(input));

    const applyAuth = (init) => {
      if (!init.headers) init.headers = new Headers();
      else if (!(init.headers instanceof Headers)) init.headers = new Headers(init.headers);
      init.headers.set("Authorization", `Bearer ${tokens[index]}`);
    };

    const origFetch = globalThis.fetch;
    globalThis.fetch = async function recursiveFetch(input, init = {}) {
      let urlStr = getUrlString(input);

      const mirrored = rewriteUrl(urlStr);
      if (mirrored) {
        log(`[mirror.fetch] REDIRECT ${urlStr} -> ${mirrored}`);
        input = typeof input === "string" ? mirrored : new Request(mirrored, input);
        urlStr = mirrored;
      }

      if (urlStr.includes("anthropic.com")) applyAuth(init);
      if (!init._skipCount) init._skipCount = 0;

      const reqSnap = snapshotInit(input, init);
      dlog(`[fetch] -> ${reqSnap.method} ${reqSnap.url}`);

      let r;
      try {
        r = await origFetch.call(globalThis, input, init);
        if (r.status === 500 && urlStr.includes("/v1/messages")) {
          for (let attempt = 1; attempt <= 3; attempt++) {
            log(`[tok-rot] 500 error (Token #${index + 1}), immediate retry ${attempt}/3...`);
            r = await origFetch.call(globalThis, input, init);
            if (r.status !== 500) break;
          }
        }
      } catch (err) {
        // Capture full context on network failure: URL, method, headers (auth redacted),
        // body summary, error name/message/stack, and which token was active.
        const ctx = {
          phase: "fetch_throw",
          url: reqSnap.url,
          method: reqSnap.method,
          token_index: index + 1,
          token_count: tokens.length,
          request: { headers: reqSnap.headers, body: reqSnap.body },
          error: err && (err.stack || err.message || String(err)),
          error_name: err && err.name,
          error_code: err && (err.code || err.errno || err.cause?.code),
        };
        log("[tok-rot] FETCH_ERROR", JSON.stringify(ctx, replacer));
        // Fall through with r=undefined so the rotation logic below can still try the next token.
      }

      if (urlStr.includes("/v1/messages")) {
        let isExhausted = false;
        let reasonLabel = "unknown";
        let respSnap = null;

        if (!r || r.status === 500) {
          isExhausted = true;
          reasonLabel = !r ? "network_error" : "persistent_500";
        } else if (r.status === 429 || r.status === 401 || r.status === 400 || r.status === 403) {
          let body;
          try { body = await r.clone().json(); } catch (_) {}
          const msg = body?.error?.message ?? "";
          const reason   = r?.headers?.get?.("anthropic-ratelimit-unified-overage-disabled-reason") || null;
          const ovStatus = r?.headers?.get?.("anthropic-ratelimit-unified-overage-status") || null;
          const hasRetry = !!r?.headers?.get?.("retry-after");

          isExhausted =
            msg.includes("OAuth authentication is currently not allowed") ||
            msg.includes("OAuth token has been revoked") ||
            msg.toLowerCase().includes("organization has been disabled") ||
            reason === "out_of_credits" ||
            ovStatus === "rejected" ||
            (!hasRetry && !reason && !ovStatus) ||
            r.statusText === "Unauthorized";

          reasonLabel = isExhausted ? "token_exhausted" : "other_4xx";

          // Always capture full failure context for /v1/messages 4xx — invaluable for tuning the
          // exhaustion heuristic above.
          respSnap = await snapshotResponse(r);
          log("[tok-rot] /v1/messages 4xx", JSON.stringify({
            phase: "non_2xx",
            url: urlStr,
            token_index: index + 1,
            token_count: tokens.length,
            decision: isExhausted ? "rotate" : "return_to_caller",
            reason_label: reasonLabel,
            heuristic: { msg, overage_reason: reason, overage_status: ovStatus, has_retry_after: hasRetry, statusText: r.statusText },
            response: respSnap,
            request: { method: reqSnap.method, headers: reqSnap.headers, body: reqSnap.body },
          }, replacer));
        }

        const MAX_SKIPS = tokens.length;
        if (isExhausted && index < tokens.length - 1 && init._skipCount < MAX_SKIPS) {
          index++;
          init._skipCount++;
          log(`[tok-rot] >>> ROTATING (${reasonLabel}) | Skip ${index}/${MAX_SKIPS} | New Token: #${index + 1}`);
          return recursiveFetch(input, init);
        }
        if (isExhausted) {
          log(`[tok-rot] EXHAUSTED — no more tokens to try (last token=#${index + 1}, total=${tokens.length})`);
        }
      }

      return r;
    };
  }

  log("[mirror] ACTIVE: GitHub mirror redirect + token rotation loaded");
})();
