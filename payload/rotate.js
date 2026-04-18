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
  const log = (...args) => {
    const ts = new Date().toLocaleString();
    try { fs.appendFileSync(LOG_FILE, `[${ts}] ${args.join(" ")}\n`); } catch (_) {}
  };

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

  const origHttpsRequest = https.request;
  https.request = function (opts, cb) {
    if (opts && typeof opts === "object" && !Buffer.isBuffer(opts)) {
      const host = opts.hostname || opts.host || "";
      const p = opts.path || "";
      if (host.includes(GCS_HOST)) {
        const mapped = rewriteMirrorPath(p);
        if (mapped) {
          log(`[mirror] REDIRECT: https://${host}${p} -> https://${mapped.host}${mapped.path}`);
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
        log(`[mirror-fetch] REDIRECT: ${urlStr} -> ${mirrored}`);
        input = typeof input === "string" ? mirrored : new Request(mirrored, input);
        urlStr = mirrored;
      }

      if (urlStr.includes("anthropic.com")) applyAuth(init);
      if (!init._skipCount) init._skipCount = 0;

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
        log(`[tok-rot] Fetch error: ${err.message}`);
      }

      if (urlStr.includes("/v1/messages")) {
        let isExhausted = false;
        let reasonLabel = "unknown";

        if (!r || r.status === 500) {
          isExhausted = true;
          reasonLabel = "persistent_500_or_net_error";
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

          reasonLabel = isExhausted ? "token_exhausted" : "other_429";
        }

        const MAX_SKIPS = 15;
        if (isExhausted && index < tokens.length - 1 && init._skipCount < MAX_SKIPS) {
          index++;
          init._skipCount++;
          log(`[tok-rot] >>> ROTATING (${reasonLabel}) | Skip ${init._skipCount}/${MAX_SKIPS} | New Token: #${index + 1}`);
          return recursiveFetch(input, init);
        }
      }

      return r;
    };
  }

  log("[mirror] ACTIVE: GitHub mirror redirect + token rotation loaded");
})();
