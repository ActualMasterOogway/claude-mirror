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

  // CLAUDE_MIRROR_DEBUG=1  → verbose per-request traces
  // CLAUDE_MIRROR_DEBUG=2  → also log full request body snapshots
  const DEBUG = parseInt(process.env.CLAUDE_MIRROR_DEBUG || "0", 10);

  const ts = () => new Date().toLocaleString();
  const log = (...args) => {
    try { fs.appendFileSync(LOG_FILE, `[${ts()}] ${args.map(stringify).join(" ")}\n`); } catch (_) {}
  };
  const dlog  = (...args) => { if (DEBUG >= 1) log("[dbg1]", ...args); };
  const dlog2 = (...args) => { if (DEBUG >= 2) log("[dbg2]", ...args); };

  // --- Safe stringifier ---
  function stringify(v) {
    if (v === null || v === undefined) return String(v);
    if (typeof v === "string") return v;
    if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint") return String(v);
    if (v instanceof Error) return `${v.name}: ${v.message}${v.stack ? "\n" + v.stack : ""}`;
    if (typeof Headers !== "undefined" && v instanceof Headers) {
      const o = {};
      try { v.forEach((val, k) => { o[k] = k.toLowerCase() === "authorization" ? redactBearer(val) : val; }); } catch (_) {}
      return JSON.stringify(o);
    }
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(v)) return `<Buffer ${v.length}B>`;
    try { return JSON.stringify(v, replacer); } catch { return String(v); }
  }
  function redactBearer(val) {
    if (typeof val !== "string") return "***";
    const m = val.match(/^(Bearer\s+)(.{6}).*(.{4})$/i);
    return m ? `${m[1]}${m[2]}…${m[3]}` : "Bearer ***";
  }
  function replacer(key, val) {
    if (key.toLowerCase && key.toLowerCase() === "authorization") return redactBearer(val);
    if (typeof Headers !== "undefined" && val instanceof Headers) {
      const o = {};
      try { val.forEach((v, k) => { o[k] = k.toLowerCase() === "authorization" ? redactBearer(v) : v; }); } catch (_) {}
      return o;
    }
    return val;
  }

  // --- Body type classifier (helps diagnose stream-consumption bugs) ---
  function classifyBody(body) {
    if (body === null || body === undefined) return "none";
    if (typeof body === "string") return `string(${body.length}B)`;
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(body)) return `Buffer(${body.length}B)`;
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return `binary(${body.byteLength}B)`;
    if (typeof ReadableStream !== "undefined" && body instanceof ReadableStream)
      return `ReadableStream(locked=${body.locked})`;
    if (body instanceof FormData) return "FormData";
    if (body instanceof URLSearchParams) return "URLSearchParams";
    if (body instanceof Blob) return `Blob(${body.size}B)`;
    if (body && (Symbol.asyncIterator in body)) return "AsyncIterator";
    return `unknown(${typeof body})`;
  }

  function snapshotInit(input, init) {
    const url    = (typeof input === "string" || input instanceof URL) ? String(input) : (input?.url || "?");
    const method = init?.method || input?.method || "GET";
    const bodyKind = classifyBody(init?.body ?? input?.body);
    let bodyPreview = null;
    if (DEBUG >= 2 && typeof init?.body === "string") {
      bodyPreview = init.body.length > 800 ? init.body.slice(0, 800) + "…" : init.body;
    }
    return { url, method, bodyKind, bodyPreview };
  }

  async function snapshotResponse(r) {
    if (!r) return { ok: false, note: "no response" };
    const hdrs = {};
    try {
      r.headers.forEach((v, k) => {
        hdrs[k] = k.toLowerCase() === "authorization" ? redactBearer(v) : v;
      });
    } catch (_) {}
    const out = { status: r.status, statusText: r.statusText, url: r.url, headers: hdrs };
    try {
      const txt = await r.clone().text();
      out.body = txt.length > 2000 ? txt.slice(0, 2000) + `…(+${txt.length - 2000}B)` : txt;
    } catch (e) { out.body_read_error = e?.message; }
    return out;
  }

  // --- Mirror config ---
  const REPO_OWNER  = "ActualMasterOogway";
  const REPO_NAME   = "claude-mirror";
  const REPO_BRANCH = "main";

  const GCS_HOST = "downloads.claude.ai";
  const GCS_PATH = "/claude-code-releases";

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

    log(`[tok-rot] Rotation ENABLED: ${tokens.length} tokens loaded`);

    const getUrlString = (input) =>
      (typeof input === "string" || input instanceof URL) ? String(input) : (input?.url || String(input));

    const applyAuth = (init) => {
      const tok = tokens[index];
      if (!init.headers) init.headers = new Headers();
      else if (!(init.headers instanceof Headers)) init.headers = new Headers(init.headers);
      init.headers.set("Authorization", `Bearer ${tok}`);
      return tok;
    };

    // Snapshot response headers relevant to rate-limiting
    function rateLimitHeaders(r) {
      const get = (h) => r?.headers?.get?.(h) || null;
      return {
        "retry-after":           get("retry-after"),
        "x-ratelimit-remaining": get("x-ratelimit-limit-requests") && get("x-ratelimit-remaining-requests"),
        "overage-reason":        get("anthropic-ratelimit-unified-overage-disabled-reason"),
        "overage-status":        get("anthropic-ratelimit-unified-overage-status"),
        "request-id":            get("request-id"),
        "cf-ray":                get("cf-ray"),
      };
    }

    // Classify WHY a token should be considered exhausted (vs. a retryable error)
    function exhaustionCheck(r, body) {
      if (!r) return { exhausted: true, reason: "no_response" };
      if (r.status === 500) return { exhausted: true, reason: "persistent_500" };

      const msg      = body?.error?.message ?? "";
      const reason   = r.headers?.get?.("anthropic-ratelimit-unified-overage-disabled-reason") || null;
      const ovStatus = r.headers?.get?.("anthropic-ratelimit-unified-overage-status") || null;
      const hasRetry = !!r.headers?.get?.("retry-after");

      // Hard exhaustion signals — token is definitely dead/blocked
      if (msg.includes("OAuth authentication is currently not allowed")) return { exhausted: true, reason: "oauth_not_allowed" };
      if (msg.includes("OAuth token has been revoked"))                   return { exhausted: true, reason: "token_revoked" };
      if (msg.toLowerCase().includes("organization has been disabled"))   return { exhausted: true, reason: "org_disabled" };
      if (r.statusText === "Unauthorized")                                return { exhausted: true, reason: "unauthorized" };
      if (r.status === 401)                                               return { exhausted: true, reason: "401" };

      // Credit/overage exhaustion
      if (reason === "out_of_credits" || reason === "org_level_disabled")
                                        return { exhausted: true,  reason: reason };
      if (ovStatus === "rejected")      return { exhausted: true,  reason: "overage_rejected" };

      // 429 WITH retry-after = normal rate limit, NOT exhausted — let the SDK handle it
      if (r.status === 429 && hasRetry) return { exhausted: false, reason: "rate_limited_retryable" };

      // 429 WITHOUT retry-after and without overage headers = likely credit exhaustion
      if (r.status === 429 && !hasRetry && !reason && !ovStatus) return { exhausted: true, reason: "429_no_retry_after" };

      // 403 without overage context = token permission/scope issue, rotate
      if (r.status === 403) return { exhausted: true, reason: "403_forbidden" };

      // 400 = request is malformed, NOT a token issue — don't rotate, return to caller
      // (rotating won't help; the same body will get the same 400 from every token)
      if (r.status === 400) return { exhausted: false, reason: "400_bad_request" };

      return { exhausted: false, reason: `other_${r.status}` };
    }

    const origFetch = globalThis.fetch;
    globalThis.fetch = async function recursiveFetch(input, init = {}) {
      let urlStr = getUrlString(input);

      const mirrored = rewriteUrl(urlStr);
      if (mirrored) {
        log(`[mirror.fetch] REDIRECT ${urlStr} -> ${mirrored}`);
        input = typeof input === "string" ? mirrored : new Request(mirrored, input);
        urlStr = mirrored;
      }

      const isMessages = urlStr.includes("/v1/messages");
      const isAnthropicApi = urlStr.includes("anthropic.com");

      if (isAnthropicApi) applyAuth(init);
      if (!init._skipCount) init._skipCount = 0;

      const reqSnap = snapshotInit(input, init);

      if (isMessages) {
        dlog(`[fetch] ${reqSnap.method} ${reqSnap.url} | token=#${index + 1}/${tokens.length} | skip=${init._skipCount} | body=${reqSnap.bodyKind}`);
        if (reqSnap.bodyPreview) dlog2(`[fetch] body-preview: ${reqSnap.bodyPreview}`);
      }

      // Warn if body type is a ReadableStream — subsequent retries cannot re-send it
      if (isMessages && init.body && typeof ReadableStream !== "undefined" && init.body instanceof ReadableStream) {
        log(`[tok-rot] WARN body is ReadableStream(locked=${init.body.locked}) — rotation retries cannot re-send this body`);
      }

      let r;
      try {
        r = await origFetch.call(globalThis, input, init);

        // 500 immediate-retry loop (same token, transient server error)
        if (r.status === 500 && isMessages) {
          for (let attempt = 1; attempt <= 3; attempt++) {
            log(`[tok-rot] 500 on token #${index + 1}, retry ${attempt}/3`);
            // NOTE: if body is a ReadableStream, this re-send will fail silently (empty body)
            r = await origFetch.call(globalThis, input, init);
            if (r.status !== 500) {
              dlog(`[tok-rot] 500 retry ${attempt} resolved to ${r.status}`);
              break;
            }
          }
        }
      } catch (err) {
        // AbortError = the SDK or user cancelled the request — NOT a token failure.
        // Re-throw immediately so the SDK sees it as a cancellation; don't rotate.
        if (err?.name === "AbortError" || err?.code === 20) {
          dlog(`[tok-rot] AbortError on token #${index + 1} — user/SDK cancel, not rotating`);
          throw err;
        }

        const ctx = {
          phase: "fetch_throw",
          url: reqSnap.url,
          method: reqSnap.method,
          token_index: index + 1,
          token_count: tokens.length,
          skip_count: init._skipCount,
          body_kind: reqSnap.bodyKind,
          error: err?.stack || err?.message || String(err),
          error_name: err?.name,
          error_code: err?.code || err?.errno || err?.cause?.code,
        };
        log("[tok-rot] FETCH_ERROR", JSON.stringify(ctx, replacer));
        // r stays undefined → exhaustion logic below can still rotate
      }

      if (isMessages) {
        let body;
        try { if (r && (r.status >= 400)) body = await r.clone().json(); } catch (_) {}

        const { exhausted, reason } = exhaustionCheck(r, body);

        const rlHdrs = rateLimitHeaders(r);

        // Always log non-2xx for /v1/messages
        if (!r || r.status >= 400) {
          const snap = await snapshotResponse(r);
          log("[tok-rot] /v1/messages non-2xx", JSON.stringify({
            url: urlStr,
            attempt: init._skipCount + 1,
            token_index: index + 1,
            token_count: tokens.length,
            decision: exhausted ? "ROTATE" : "return_to_caller",
            exhaustion_reason: reason,
            rate_limit_headers: rlHdrs,
            error_msg: body?.error?.message,
            error_type: body?.error?.type ?? null,
            status: r?.status,
            statusText: r?.statusText,
            body: snap?.body,
            body_kind: reqSnap.bodyKind,
          }, replacer));
        } else if (init._skipCount > 0) {
          // Log success after rotation so we know which token worked
          log(`[tok-rot] ✓ SUCCESS after ${init._skipCount} skip(s) | token=#${index + 1} | status=${r.status}`);
        }

        const MAX_SKIPS = tokens.length;
        if (exhausted && index < tokens.length - 1 && init._skipCount < MAX_SKIPS) {
          const prevIndex = index;
          index++;
          init._skipCount++;
          log(`[tok-rot] ROTATING: token #${prevIndex + 1} exhausted (${reason}) → trying token #${index + 1} | skip=${init._skipCount}/${MAX_SKIPS}`);
          return recursiveFetch(input, init);
        }

        if (exhausted) {
          log(`[tok-rot] ALL TOKENS EXHAUSTED (last=${reason}) | tried ${init._skipCount + 1} token(s) | resetting index to 0`);
          index = 0;
        }
      }

      return r;
    };
  }

  log("[mirror] ACTIVE: GitHub mirror redirect + token rotation loaded");
})();
