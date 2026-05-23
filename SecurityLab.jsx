import { useState, useEffect, useCallback } from "react";

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function highlightDangerous(str) {
  const parts = [];
  const regex = /([<>'"])/g;
  let last = 0;
  let match;
  let key = 0;
  while ((match = regex.exec(str)) !== null) {
    if (match.index > last) {
      parts.push(<span key={key++}>{str.slice(last, match.index)}</span>);
    }
    parts.push(
      <span
        key={key++}
        className="text-red-400 bg-red-900/40 px-0.5 rounded font-bold"
      >
        {match[0]}
      </span>
    );
    last = match.index + match[0].length;
  }
  if (last < str.length) {
    parts.push(<span key={key++}>{str.slice(last)}</span>);
  }
  return parts;
}

const XSS_PATTERN = /<script|onerror\s*=|onload\s*=|javascript:/i;
const SQLI_PATTERN = /'\s*or\s|'\s*or\s*1\s*=\s*1|--|drop\s+table|select\s+\*\s+from/i;

function detectThreats(input) {
  const xss = XSS_PATTERN.test(input);
  const sqli = SQLI_PATTERN.test(input);
  if (xss && sqli) return { type: "both", xss: true, sqli: true };
  if (xss) return { type: "xss", xss: true, sqli: false };
  if (sqli) return { type: "sqli", xss: false, sqli: true };
  return { type: "none", xss: false, sqli: false };
}

export default function WebSecurityLab() {
  const [mode, setMode] = useState("vulnerable");
  const [comment, setComment] = useState("");
  const [postedComment, setPostedComment] = useState("");
  const [postedMode, setPostedMode] = useState("vulnerable");
  const [copied, setCopied] = useState(false);
  const [showXssToast, setShowXssToast] = useState(false);
  const [showSqliToast, setShowSqliToast] = useState(false);

  const threats = detectThreats(comment);
  const isVulnerable = mode === "vulnerable";

  const handlePost = () => {
    if (!comment.trim()) return;
    setPostedComment(comment);
    setPostedMode(mode);
    setShowXssToast(false);
    setShowSqliToast(false);
    if (mode === "vulnerable") {
      const t = detectThreats(comment);
      if (t.xss) {
        setTimeout(() => setShowXssToast(true), 100);
        setTimeout(() => setShowXssToast(false), 5000);
      }
      if (t.sqli) {
        setTimeout(() => setShowSqliToast(true), 200);
        setTimeout(() => setShowSqliToast(false), 5000);
      }
    }
  };

  const handleClear = () => {
    setComment("");
    setPostedComment("");
    setShowXssToast(false);
    setShowSqliToast(false);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(escapeHtml(comment)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const postedThreats = detectThreats(postedComment);

  return (
    <div className="flex flex-col md:flex-row h-screen overflow-hidden font-sans bg-slate-950">

      {/* ── LEFT HALF ─────────────────────────────────── */}
      <div className="flex flex-col md:w-1/2 w-full bg-gradient-to-br from-white to-slate-50 overflow-y-auto border-r border-slate-200 shadow-xl">
        <div className="p-6 flex flex-col gap-5 min-h-full">

          {/* Title */}
          <div>
            <h1 className="text-2xl font-bold text-slate-800 tracking-tight flex items-center gap-2">
              <span>🛡️</span> Web Security Interactive Lab
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Compare vulnerable vs. secure input handling in real time
            </p>
          </div>

          {/* Mode Toggle */}
          <div className="flex items-center gap-3">
            <span
              className={`text-sm font-semibold transition-colors duration-300 ${
                !isVulnerable ? "text-slate-400" : "text-red-600"
              }`}
            >
              Vulnerable
            </span>
            <button
              onClick={() => setMode(isVulnerable ? "secure" : "vulnerable")}
              aria-label="Toggle security mode"
              className={`relative w-14 h-7 rounded-full transition-colors duration-300 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 ${
                isVulnerable
                  ? "bg-red-500"
                  : "bg-emerald-500"
              }`}
            >
              <span
                className={`absolute top-0.5 w-6 h-6 bg-white rounded-full shadow-md transition-transform duration-300 ${
                  isVulnerable ? "left-0.5 translate-x-0" : "left-0.5 translate-x-7"
                }`}
              />
            </button>
            <span
              className={`text-sm font-semibold transition-colors duration-300 ${
                isVulnerable ? "text-slate-400" : "text-emerald-600"
              }`}
            >
              Secure
            </span>
            <span
              className={`ml-2 text-xs font-bold px-2.5 py-1 rounded-full transition-all duration-300 ${
                isVulnerable
                  ? "bg-red-100 text-red-700 border border-red-200"
                  : "bg-emerald-100 text-emerald-700 border border-emerald-200"
              }`}
            >
              {isVulnerable ? "VULNERABLE MODE" : "SECURE MODE"}
            </span>
          </div>

          {/* Textarea */}
          <div>
            <label className="block text-sm font-medium text-slate-600 mb-1.5">
              Comment Input
            </label>
            <textarea
              className="w-full border border-slate-200 rounded-xl p-3.5 text-sm text-slate-800 placeholder-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent shadow-sm resize-none font-mono transition"
              rows={4}
              placeholder={"Write a comment… (try <script>alert('XSS')</script> or SQL injection: ' OR 1=1 --)"}
              value={comment}
              onChange={(e) => setComment(e.target.value)}
            />
          </div>

          {/* Buttons */}
          <div className="flex gap-3">
            <button
              onClick={handlePost}
              className="flex-1 bg-gradient-to-r from-indigo-500 to-violet-600 text-white text-sm font-semibold py-2.5 px-5 rounded-xl shadow-md hover:from-indigo-600 hover:to-violet-700 active:scale-95 transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-indigo-400"
            >
              Post Comment
            </button>
            <button
              onClick={handleClear}
              className="px-5 py-2.5 text-sm font-semibold bg-slate-100 text-slate-600 rounded-xl hover:bg-slate-200 active:scale-95 transition-all duration-150 border border-slate-200"
            >
              Clear
            </button>
          </div>

          {/* Posted Comment Preview */}
          {postedComment && (
            <div className="mt-1">
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-2">
                Posted Preview
              </p>

              {/* Simulated XSS Alert Toast */}
              {showXssToast && (
                <div className="mb-3 bg-red-600 text-white rounded-xl p-3 shadow-lg border-2 border-red-400 animate-pulse flex items-start gap-2">
                  <span className="text-xl">🚨</span>
                  <div>
                    <p className="font-bold text-sm">XSS Attack Executed! (simulated)</p>
                    <p className="text-xs opacity-90 mt-0.5">
                      alert('hacked') would pop up in the victim's browser, stealing cookies or session tokens.
                    </p>
                  </div>
                </div>
              )}

              {/* Simulated SQLi Toast */}
              {showSqliToast && (
                <div className="mb-3 bg-orange-600 text-white rounded-xl p-3 shadow-lg border-2 border-orange-400 flex items-start gap-2">
                  <span className="text-xl">⚠️</span>
                  <div>
                    <p className="font-bold text-sm">SQL Injection payload submitted</p>
                    <p className="text-xs opacity-90 mt-0.5">
                      In a real app, this could return all users or delete your database.
                    </p>
                  </div>
                </div>
              )}

              <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-sm">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-9 h-9 rounded-full bg-indigo-100 flex items-center justify-center text-xs font-bold text-indigo-700 shrink-0">
                    USR
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-slate-800">User123</p>
                    <p className="text-xs text-slate-400">just now</p>
                  </div>
                  <span
                    className={`ml-auto text-xs font-semibold px-2 py-0.5 rounded-full ${
                      postedMode === "vulnerable"
                        ? "bg-red-100 text-red-600"
                        : "bg-emerald-100 text-emerald-600"
                    }`}
                  >
                    {postedMode === "vulnerable" ? "raw HTML" : "sanitized"}
                  </span>
                </div>
                <div className="text-sm text-slate-700 break-words leading-relaxed">
                  {postedMode === "vulnerable" ? (
                    <span
                      dangerouslySetInnerHTML={{ __html: postedComment }}
                    />
                  ) : (
                    <span>{postedComment}</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {!postedComment && (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center text-slate-300 select-none">
                <div className="text-4xl mb-2">💬</div>
                <p className="text-sm">Posted comments will appear here</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── RIGHT HALF – SECURITY CONSOLE ──────────────── */}
      <div
        className="flex flex-col md:w-1/2 w-full bg-slate-900 text-slate-100 overflow-y-auto"
        style={{
          backgroundImage:
            "repeating-linear-gradient(0deg, transparent, transparent 28px, rgba(148,163,184,0.04) 28px, rgba(148,163,184,0.04) 29px)",
        }}
      >
        <div className="p-6 flex flex-col gap-5">

          {/* Console header */}
          <div className="flex items-center gap-2 pb-1 border-b border-slate-700/60">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500/70" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
              <div className="w-3 h-3 rounded-full bg-green-500/70" />
            </div>
            <span className="text-xs font-mono text-slate-500 ml-2 tracking-widest uppercase">
              security-console — live feed
            </span>
          </div>

          {/* ── STATUS BADGE ─────────────────────────── */}
          {isVulnerable ? (
            <div className="flex items-center gap-3 bg-red-900/40 border-2 border-red-500/60 rounded-2xl px-5 py-4 animate-pulse">
              <span className="text-2xl shrink-0">🛡️</span>
              <div>
                <p className="text-red-300 font-bold text-sm tracking-wide uppercase">
                  ⚠️ SYSTEM VULNERABLE
                </p>
                <p className="text-red-400/80 text-xs font-mono mt-0.5">
                  Unescaped Output — Raw HTML injected into DOM
                </p>
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-3 bg-emerald-900/30 border-2 border-emerald-500/60 rounded-2xl px-5 py-4 ring-1 ring-emerald-400/20">
              <span className="text-2xl shrink-0">🛡️</span>
              <div>
                <p className="text-emerald-300 font-bold text-sm tracking-wide uppercase">
                  🛡️ SYSTEM SECURE
                </p>
                <p className="text-emerald-400/70 text-xs font-mono mt-0.5">
                  Sanitized Output — All special chars escaped
                </p>
              </div>
            </div>
          )}

          {/* ── THREAT DETECTION ─────────────────────── */}
          <div className="rounded-xl border border-slate-700/60 bg-slate-800/50 p-4">
            <p className="text-xs font-mono text-slate-400 uppercase tracking-widest mb-3">
              ▶ threat_detection.analyze()
            </p>

            {threats.type !== "none" && isVulnerable && (
              <div className="bg-red-950/70 border-2 border-red-500 rounded-xl p-4 mb-3 animate-pulse">
                <p className="text-red-300 font-bold text-sm mb-1">🚨 SYSTEM COMPROMISED</p>
                {threats.type === "both" && (
                  <p className="text-red-400/90 text-xs font-mono">
                    Multiple attack vectors detected: XSS + SQL Injection
                  </p>
                )}
                {threats.xss && (
                  <p className="text-red-400/90 text-xs font-mono mt-1">
                    Stored XSS: Attacker's script will execute in victim's browser, stealing cookies or redirecting them.
                  </p>
                )}
                {threats.sqli && (
                  <p className="text-orange-400/90 text-xs font-mono mt-1">
                    SQL Injection: This input could alter the database query, exposing or deleting data.
                  </p>
                )}
              </div>
            )}

            {threats.type !== "none" && !isVulnerable && (
              <div className="bg-emerald-900/30 border border-emerald-500/60 rounded-xl p-3 mb-3">
                <p className="text-emerald-300 text-xs font-mono">
                  ✅ Potential threat detected, but input is sanitized.
                  No script execution possible.
                </p>
              </div>
            )}

            {threats.type === "none" && (
              <div className="text-slate-400 text-xs font-mono">
                {isVulnerable
                  ? "✅  No suspicious patterns found — currently safe"
                  : "✅  Input appears safe — no attack vectors detected"}
              </div>
            )}

            {threats.type !== "none" && (
              <div className="flex gap-2 flex-wrap mt-2">
                {threats.xss && (
                  <span className="text-xs bg-red-900/50 text-red-300 border border-red-700/50 px-2 py-0.5 rounded-full font-mono">
                    XSS detected
                  </span>
                )}
                {threats.sqli && (
                  <span className="text-xs bg-orange-900/50 text-orange-300 border border-orange-700/50 px-2 py-0.5 rounded-full font-mono">
                    SQLi detected
                  </span>
                )}
              </div>
            )}
          </div>

          {/* ── SANITIZED CODE OUTPUT ────────────────── */}
          <div className="rounded-xl border border-slate-700/60 bg-slate-800/50 p-4 flex-1">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">
                ▶ output_handler.process()
              </p>
              {!isVulnerable && comment && (
                <button
                  onClick={handleCopy}
                  className="text-xs font-mono bg-emerald-900/50 hover:bg-emerald-800/70 text-emerald-300 border border-emerald-700/50 px-2.5 py-1 rounded-lg transition-colors active:scale-95"
                >
                  {copied ? "✓ Copied!" : "Copy sanitized"}
                </button>
              )}
            </div>

            {isVulnerable ? (
              <>
                <div className="mb-2">
                  <span className="text-xs font-mono bg-red-900/30 text-red-400 border border-red-800/40 px-2 py-0.5 rounded">
                    RAW OUTPUT — UNESCAPED — will be injected directly into HTML
                  </span>
                </div>
                <pre className="bg-slate-900/80 border border-slate-700/50 text-slate-200 font-mono text-xs p-4 rounded-lg overflow-x-auto whitespace-pre-wrap break-words min-h-[60px]">
                  <code>{comment ? highlightDangerous(comment) : <span className="text-slate-600">// input will appear here…</span>}</code>
                </pre>
                <p className="text-red-400/70 text-xs font-mono mt-2">
                  ⚠ This is exactly what gets sent to the browser. An attacker's code will execute.
                </p>
              </>
            ) : (
              <>
                <div className="mb-2">
                  <span className="text-xs font-mono bg-emerald-900/30 text-emerald-400 border border-emerald-800/40 px-2 py-0.5 rounded">
                    SANITIZED OUTPUT — ESCAPED — safe to render
                  </span>
                </div>
                <pre className="bg-slate-900/80 border border-emerald-900/40 text-emerald-300 font-mono text-xs p-4 rounded-lg overflow-x-auto whitespace-pre-wrap break-words min-h-[60px]">
                  <code>{comment ? escapeHtml(comment) : <span className="text-slate-600">// input will appear here…</span>}</code>
                </pre>
                <p className="text-emerald-400/70 text-xs font-mono mt-2">
                  ✅ Special characters are escaped so the browser treats them as text, not code.
                </p>
              </>
            )}
          </div>

          {/* Console footer */}
          <div className="text-xs font-mono text-slate-600 border-t border-slate-800 pt-3 flex justify-between">
            <span>mode: <span className={isVulnerable ? "text-red-400" : "text-emerald-400"}>{mode}</span></span>
            <span>chars: {comment.length}</span>
            <span>threat: <span className={threats.type !== "none" ? "text-red-400" : "text-slate-500"}>{threats.type}</span></span>
          </div>
        </div>
      </div>
    </div>
  );
}
