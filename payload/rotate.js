;(() => {
  // ── Module acquisition ────────────────────────────────────────────────────
  // CJS (2.1.241 and earlier): require is injected as a function parameter by
  // the Bun CJS wrapper, so it is always available.
  // ESM (2.1.242+): require does not exist; we fall back to dynamic import().
  // Everything that needs fs or https is deferred into _onModules(), which is
  // called synchronously in CJS and from a Promise .then() in ESM.  The fetch
  // hook and token-rotation logic do NOT need those modules and are wired up
  // immediately so no early fetch call is missed.
  const _cjsRequire = typeof require === "function" ? require : null;

  // ── Log file path (no path module needed) ────────────────────────────────
  // Build the path with plain string concat — safe on all platforms supported
  // by Claude Code (POSIX and Windows both accept forward slashes here).
  const _logDir  = (process.env.USERPROFILE || process.env.HOME || ".") + "/.claude";
  const LOG_FILE = _logDir + "/tok-rot.log";

  // CLAUDE_MIRROR_DEBUG=1  → verbose per-request traces
  // CLAUDE_MIRROR_DEBUG=2  → also log full request body snapshots
  const DEBUG = parseInt(process.env.CLAUDE_MIRROR_DEBUG || "0", 10);

  // ── Buffered logging ──────────────────────────────────────────────────────
  // In the ESM code path, fs is not available synchronously.  Log lines are
  // accumulated in _logBuf and flushed to disk once _onModules() fires.
  let _fs = null;
  const _logBuf = [];
  const ts = () => new Date().toLocaleString();
  const log = (...args) => {
    const line = `[${ts()}] ${args.map(stringify).join(" ")}\n`;
    if (_fs) {
      try { _fs.appendFileSync(LOG_FILE, line); } catch (_) {}
    } else {
      _logBuf.push(line);
    }
  };
  const dlog  = (...args) => { if (DEBUG >= 1) log("[dbg1]", ...args); };
  const dlog2 = (...args) => { if (DEBUG >= 2) log("[dbg2]", ...args); };

  // --- Safe stringifier ---
  const SENSITIVE_HEADERS = new Set(["authorization", "x-api-key"]);
  function stringify(v) {
    if (v === null || v === undefined) return String(v);
    if (typeof v === "string") return v;
    if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint") return String(v);
    if (v instanceof Error) return `${v.name}: ${v.message}${v.stack ? "\n" + v.stack : ""}`;
    if (typeof Headers !== "undefined" && v instanceof Headers) {
      const o = {};
      try { v.forEach((val, k) => { o[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? redactSecret(val) : val; }); } catch (_) {}
      return JSON.stringify(o);
    }
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(v)) return `<Buffer ${v.length}B>`;
    try { return JSON.stringify(v, replacer); } catch { return String(v); }
  }
  function redactSecret(val) {
    if (typeof val !== "string") return "***";
    const m = val.match(/^(\s*bearer\s+)?(.{6}).*(.{4})$/i);
    return m ? `${m[1] || ""}${m[2]}…${m[3]}` : "***";
  }
  function replacer(key, val) {
    if (key.toLowerCase && SENSITIVE_HEADERS.has(key.toLowerCase())) return redactSecret(val);
    if (typeof Headers !== "undefined" && val instanceof Headers) {
      const o = {};
      try { val.forEach((v, k) => { o[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? redactSecret(v) : v; }); } catch (_) {}
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
        hdrs[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? redactSecret(v) : v;
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

  // ── https.request hook (installed once fs/https are available) ────────────
  function _installHttpsHook(https) {
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
  }

  // ── Called once fs (and optionally https) are available ──────────────────
  function _onModules(fs, https) {
    _fs = fs;
    // Flush any log lines buffered before fs was ready
    if (_logBuf.length) {
      try { fs.mkdirSync(_logDir, { recursive: true }); } catch (_) {}
      const pending = _logBuf.splice(0).join("");
      try { fs.appendFileSync(LOG_FILE, pending); } catch (_) {}
    } else {
      try { fs.mkdirSync(_logDir, { recursive: true }); } catch (_) {}
    }
    if (https) _installHttpsHook(https);
    log("[mirror] ACTIVE: GitHub mirror redirect + token rotation loaded");
  }

  // --- Token rotation + Anthropic proxy ---
  // Credential families in Claude Code's own resolution order (see extraction:
  // dN()/eO() as surfaced by /status — token sources beat ANTHROPIC_API_KEY,
  // and within tokens ANTHROPIC_AUTH_TOKEN beats CLAUDE_CODE_OAUTH_TOKEN).
  // Wire format per family: tokens -> "Authorization: Bearer <cred>",
  // ANTHROPIC_API_KEY -> "x-api-key: <key>" (in OAuth mode the client nulls its
  // apiKey entirely, so only one family is ever active at a time).
  const CREDENTIAL_FAMILIES = [
    { env: "ANTHROPIC_AUTH_TOKEN",    style: "bearer" },
    { env: "CLAUDE_CODE_OAUTH_TOKEN", style: "bearer" },
    { env: "ANTHROPIC_API_KEY",       style: "api-key" },
  ];
  // Splitter is deliberately liberal about list format: commas, newlines,
  // semicolons and whitespace all separate credentials (tokens themselves
  // never contain any of those), so a pasted column of 300+ tokens works
  // the same as a comma-joined one-liner.
  const parseCreds = (v) => (v || "").split(/[\s,;]+/).filter(Boolean);

  const activeFam = (() => {
    for (const fam of CREDENTIAL_FAMILIES) {
      const creds = parseCreds(process.env[fam.env]);
      if (creds.length) return { ...fam, creds };
    }
    return null;
  })();

  // Startup diagnostics: log every family's parsed count so concurrent
  // sessions sharing tok-rot.log are easy to tell apart (ASCII only — the log
  // gets read on Windows consoles where UTF-8 punctuation turns to mojibake).
  const famCounts = CREDENTIAL_FAMILIES
    .map(f => {
      const raw = process.env[f.env] || "";
      return `${f.env}=${parseCreds(raw).length}(${raw.length}ch)`;
    })
    .join(" ");
  log(`[tok-rot] pid=${process.pid} creds: ${famCounts}`);

  if (!activeFam) {
    log("[tok-rot] pid=" + process.pid + " no credential env vars set (ANTHROPIC_AUTH_TOKEN / CLAUDE_CODE_OAUTH_TOKEN / ANTHROPIC_API_KEY) - auth pass-through");
  } else if (activeFam.creds.length < 2) {
    log(`[tok-rot] pid=${process.pid} found ${activeFam.creds.length} ${activeFam.env} credential, rotation disabled - single-credential pass-through`);
  } else {
    const { env: AUTH_ENV, style: AUTH_STYLE, creds: tokens } = activeFam;
    let index = 0;
    const getTok = () => tokens[index] ?? tokens[0];

    // Install a live, read-only <active family env var> on process.env so every
    // read the host does (see extraction: it reads process.env.CLAUDE_CODE_OAUTH_TOKEN
    // to build the accessToken, and process.env.ANTHROPIC_API_KEY when resolving
    // apiKey credentials) returns the CURRENT rotated credential, and every write
    // the host attempts (refresh paths do `process.env.CLAUDE_CODE_OAUTH_TOKEN = ...`)
    // is swallowed so it can't clobber our rotation.
    //
    // Node: an accessor property descriptor on process.env works directly.
    // Bun (v1.4+): process.env rejects accessor descriptors
    // ("'process.env' does not accept an accessor(getter/setter) descriptor"),
    // so we instead swap process.env for a Proxy that special-cases our key.
    const installRotatingCred = () => {
      // Path 1 — Node: accessor directly on process.env.
      try {
        Object.defineProperty(process.env, AUTH_ENV, {
          get: getTok,
          set: () => {},
          configurable: true,
          enumerable: true,
        });
        if (process.env[AUTH_ENV] === getTok()) return "env-accessor";
      } catch (_) { /* fall through to Bun path */ }

      // Path 2 — Bun: wrap process.env in a Proxy that intercepts our key.
      try {
        const realEnv = process.env;
        const proxy = new Proxy(realEnv, {
          get(t, p) { return p === AUTH_ENV ? getTok() : t[p]; },
          set(t, p, v) {
            if (p === AUTH_ENV) return true; // swallow host writes
            t[p] = v; return true;
          },
          deleteProperty(t, p) {
            if (p === AUTH_ENV) return true; // protect from delete
            delete t[p]; return true;
          },
          has(t, p) { return p === AUTH_ENV ? true : (p in t); },
        });
        try {
          Object.defineProperty(process, "env", {
            get: () => proxy,
            set: () => {},
            configurable: true,
            enumerable: true,
          });
        } catch (_) {
          process.env = proxy;
        }
        if (process.env[AUTH_ENV] === getTok()) return "env-proxy";
      } catch (_) {}

      return "failed";
    };

    const tokMode = installRotatingCred();
    if (tokMode === "failed") {
      log(`[tok-rot] WARN could not install live ${AUTH_ENV} accessor; rotation still applies via fetch headers`);
    } else {
      log(`[tok-rot] live ${AUTH_ENV} accessor installed via ${tokMode}`);
    }

    log(`[tok-rot] Rotation ENABLED via ${AUTH_ENV} (${AUTH_STYLE}): ${tokens.length} credentials loaded`);

    const getUrlString = (input) =>
      (typeof input === "string" || input instanceof URL) ? String(input) : (input?.url || String(input));

    const applyAuth = (init) => {
      const cred = tokens[index];
      if (!init.headers) init.headers = new Headers();
      else if (!(init.headers instanceof Headers)) init.headers = new Headers(init.headers);
      if (AUTH_STYLE === "api-key") {
        // eO(): API-key sources ride x-api-key with NO Bearer header — drop any
        // stale Authorization so the rotated key stays authoritative.
        init.headers.delete("Authorization");
        init.headers.set("x-api-key", cred);
      } else {
        init.headers.set("Authorization", `Bearer ${cred}`);
      }
      return cred;
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

    // Classify WHY a credential should be considered exhausted (vs. a retryable
    // or request-scoped error). Rotating only helps when the CREDENTIAL is the
    // problem — bad key, revoked/no-user org, no payment/credits, or a hard
    // quota wall — so everything else is returned to the caller untouched.
    // Taxonomy follows Anthropic's error protocol: structured
    // {error:{type,message}} bodies (authentication_error, billing_error,
    // permission_error, rate_limit_error, not_found_error, invalid_request_error,
    // api_error, overloaded_error) plus the subscription-only
    // anthropic-ratelimit-unified-overage-* headers.
    function exhaustionCheck(r, body) {
      if (!r) return { exhausted: true, reason: "no_response" };

      const etype    = body?.error?.type ?? null;
      const msg      = (body?.error?.message ?? "").toLowerCase();
      const reason   = r.headers?.get?.("anthropic-ratelimit-unified-overage-disabled-reason") || null;
      const ovStatus = r.headers?.get?.("anthropic-ratelimit-unified-overage-status") || null;
      const hasRetry = !!r.headers?.get?.("retry-after");

      // Credential-definite failures — key/token/user/org is dead or blocked
      if (etype === "authentication_error")                              return { exhausted: true, reason: "auth_failed_40x" };
      if (msg.includes("oauth authentication is currently not allowed")) return { exhausted: true, reason: "oauth_not_allowed" };
      if (msg.includes("oauth token has been revoked"))                  return { exhausted: true, reason: "token_revoked" };
      if (msg.includes("organization has been disabled"))                return { exhausted: true, reason: "org_disabled" };
      if (r.status === 401)                                              return { exhausted: true, reason: "401_unauthorized" };

      // No payment / credit exhaustion. NOTE: console keys report this as
      // 400 billing_error ("credit balance is too low"), NOT 429 — a plain
      // "don't rotate on 400" rule would never advance past an empty wallet.
      if (etype === "billing_error")                                     return { exhausted: true, reason: "billing_error" };
      if (msg.includes("credit balance is too low"))                     return { exhausted: true, reason: "out_of_credits" };
      if (reason === "out_of_credits" || reason === "org_level_disabled" || reason === "org_level_disabled_until")
                                                                         return { exhausted: true, reason: reason };
      if (ovStatus === "rejected")                                       return { exhausted: true, reason: "overage_rejected" };

      // Rate limiting. 429 WITH retry-after = ordinary shared-limit backoff,
      // NOT exhausted — let the SDK wait and reuse this credential. Without
      // retry-after and without overage context = this credential's quota wall.
      if (r.status === 429 && hasRetry) return { exhausted: false, reason: "rate_limited_retryable" };
      if (r.status === 429)             return { exhausted: true,  reason: "429_no_retry_after" };

      // Permission/scope failure on this credential (blocked feature, gated org)
      if (r.status === 403 && (etype === "permission_error" || !etype)) return { exhausted: true, reason: "403_permission" };

      // Request-scoped failures — rotating cannot help; surface to caller
      if (r.status === 400) return { exhausted: false, reason: `400_${etype || "bad_request"}` };
      if (r.status === 404) return { exhausted: false, reason: `404_${etype || "not_found"}` };
      if (r.status === 413 || r.status === 422) return { exhausted: false, reason: `request_rejected_${r.status}` };
      if (r.status === 529) return { exhausted: false, reason: "overloaded_529" };

      // Survived the same-token 500 retry loop above — treat as poisoned
      if (r.status === 500) return { exhausted: true, reason: "persistent_500" };

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

      // Endpoint detection. Host-based for anthropic.com; path-based for custom
      // gateways (ANTHROPIC_BASE_URL): a /v1/messages path IS the Anthropic
      // protocol signature (OpenAI-style proxies use /chat/completions). Match
      // anywhere in the path because gateways mount it under subpaths, e.g.
      // https://openrouter.ai/api + /v1/messages -> /api/v1/messages.
      let u = null;
      try { u = new URL(urlStr); } catch (_) {}
      const isAnthropicHost = !!u && /(^|\.)anthropic\.com$/i.test(u.hostname);
      const isMessagesPath  = !!u && u.pathname.includes("/v1/messages");
      const isMessages      = isMessagesPath;
      const isAnthropicApi  = isAnthropicHost || isMessagesPath;

      if (isAnthropicApi) applyAuth(init);
      if (!init._skipCount) init._skipCount = 0;

      const reqSnap = snapshotInit(input, init);

      if (isMessages) {
        dlog(`[fetch] ${reqSnap.method} ${reqSnap.url} | ${AUTH_ENV}=#${index + 1}/${tokens.length} | skip=${init._skipCount} | body=${reqSnap.bodyKind}`);
        if (reqSnap.bodyPreview) dlog2(`[fetch] body-preview: ${reqSnap.bodyPreview}`);
      }

      // Warn if body type is a ReadableStream — subsequent retries cannot re-send it
      if (isMessages && init.body && typeof ReadableStream !== "undefined" && init.body instanceof ReadableStream) {
        log(`[tok-rot] WARN body is ReadableStream(locked=${init.body.locked}) - rotation retries cannot re-send this body`);
      }

      let r;
      try {
        r = await origFetch.call(globalThis, input, init);

        // 500 immediate-retry loop (same token, transient server error)
        if (r.status === 500 && isMessages) {
          for (let attempt = 1; attempt <= 3; attempt++) {
            log(`[tok-rot] 500 on credential #${index + 1} (${AUTH_ENV}), retry ${attempt}/3`);
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
          dlog(`[tok-rot] AbortError on credential #${index + 1} - user/SDK cancel, not rotating`);
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
            source: AUTH_ENV,
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
          log(`[tok-rot] OK SUCCESS after ${init._skipCount} skip(s) | ${AUTH_ENV}=#${index + 1} | status=${r.status}`);
        }

        const MAX_SKIPS = tokens.length;
        if (exhausted && index < tokens.length - 1 && init._skipCount < MAX_SKIPS) {
          const prevIndex = index;
          index++;
          init._skipCount++;
          log(`[tok-rot] ROTATING: ${AUTH_ENV} #${prevIndex + 1} exhausted (${reason}) -> trying #${index + 1} | skip=${init._skipCount}/${MAX_SKIPS}`);
          return recursiveFetch(input, init);
        }

        if (exhausted) {
          log(`[tok-rot] ALL ${AUTH_ENV} CREDENTIALS EXHAUSTED (last=${reason}) | tried ${init._skipCount + 1} credential(s) | resetting index to 0`);
          index = 0;
        }
      }

      return r;
    };
  }

  // ── Acquire fs + https, then complete initialisation ─────────────────────
  // CJS path: synchronous — _onModules fires before any other code in this
  // module sees the fetch / https hooks.
  // ESM path: Promise.all resolves as microtasks before the first awaited
  // statement in the entry module body runs, so hooks are in place before any
  // real async work (API calls, update checks) begins.
  if (_cjsRequire) {
    _onModules(_cjsRequire("fs"), _cjsRequire("https"));
  } else {
    Promise.all([
      import("node:fs"),
      import("node:https"),
    ]).then(([fsM, httpsM]) => {
      // Dynamic import returns the module namespace; named exports are direct
      // properties (no .default wrapper needed for Node built-ins in Bun ESM).
      _onModules(fsM.default || fsM, httpsM.default || httpsM);
    }).catch(() => {});
  }
})();
