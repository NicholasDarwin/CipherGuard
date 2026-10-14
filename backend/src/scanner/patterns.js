// Pattern rules for the line-level scanner. Each rule has a title shown in the
// report, a severity, and a fixed remediation so a report is actionable even
// when AI analysis is off.

const ROTATE =
  "Revoke the credential with its issuer and issue a new one, move it to an " +
  "environment variable or secret manager, then remove it from git history " +
  "(git filter-repo or BFG). Deleting it in a new commit does not un-leak it.";

const SECRET_PATTERNS = {
  private_key: {
    pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/,
    severity: "critical",
    title: "Private key committed",
    remediation: ROTATE,
  },
  aws_secret: {
    pattern: /aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}/i,
    severity: "critical",
    title: "AWS secret access key",
    remediation: ROTATE,
  },
  aws_access_key: {
    pattern: /(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}/,
    severity: "critical",
    title: "AWS access key ID",
    remediation: ROTATE,
  },
  github_token: {
    pattern: /(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/,
    severity: "critical",
    title: "GitHub personal access token",
    remediation: ROTATE,
  },
  stripe_secret: {
    pattern: /sk_live_[a-zA-Z0-9]{24,}/,
    severity: "critical",
    title: "Stripe live secret key",
    remediation: ROTATE,
  },
  slack_token: {
    pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/,
    severity: "critical",
    title: "Slack token",
    remediation: ROTATE,
  },
  api_key: {
    pattern: /(api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9_-]{20,}["']?/i,
    severity: "high",
    title: "Hardcoded API key",
    remediation: ROTATE,
  },
  token: {
    pattern: /(token|auth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[=:]\s*["']?[A-Za-z0-9_\-.]{20,}["']?/i,
    severity: "high",
    title: "Hardcoded auth token",
    remediation: ROTATE,
  },
  secret: {
    pattern: /(secret|client[_-]?secret|app[_-]?secret)\s*[=:]\s*["']?[A-Za-z0-9_-]{16,}["']?/i,
    severity: "high",
    title: "Hardcoded client secret",
    remediation: ROTATE,
  },
  bearer: {
    pattern: /["']?bearer\s+[A-Za-z0-9_\-.]{20,}["']?/i,
    severity: "high",
    title: "Bearer token in source",
    remediation: ROTATE,
  },
  jwt: {
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/,
    severity: "high",
    title: "JSON Web Token in source",
    remediation:
      "If the token is live, revoke it or rotate the signing key. Load tokens " +
      "at runtime; never commit them, even for tests.",
  },
  google_api: {
    pattern: /AIza[0-9A-Za-z_-]{35}/,
    severity: "high",
    title: "Google API key",
    remediation: ROTATE,
  },
  password: {
    pattern: /(password|passwd|pwd|pass)\s*[=:]\s*["']?[^\s"']{6,}["']?/i,
    severity: "medium",
    title: "Password in source",
    remediation:
      "Change the password wherever it is used, then read it from the " +
      "environment or a secret manager instead of the source file.",
  },
  authorization: {
    pattern: /authorization\s*[=:]\s*["']?[A-Za-z0-9_\-.]+["']?/i,
    severity: "medium",
    title: "Authorization header value",
    remediation: ROTATE,
  },
  database_url: {
    pattern: /(mongodb|mysql|postgres|postgresql|redis):\/\/[^\s"']+/i,
    severity: "medium",
    title: "Database connection string",
    remediation:
      "If the URL embeds credentials, rotate them. Supply the connection " +
      "string through an environment variable such as DATABASE_URL.",
  },
  connection_string: {
    pattern: /(connection[_-]?string|conn[_-]?str)\s*[=:]\s*["']?[^\s"']+["']?/i,
    severity: "medium",
    title: "Connection string",
    remediation:
      "Move the connection string to configuration that is not committed, " +
      "and rotate any credentials it contains.",
  },
  email: {
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
    severity: "info",
    title: "Email address",
    remediation:
      "Usually harmless. Remove it if it identifies a private person or an " +
      "internal mailbox.",
  },
  ip_address: {
    // Real IPv4 only: every octet 0-255, and not inside a longer number or
    // decimal run (e.g. SVG path data "12.5.3.1.7").
    pattern:
      /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}(?![\d.])/,
    severity: "low",
    title: "Hardcoded IP address",
    remediation:
      "Move hosts to configuration so environments can differ and internal " +
      "addresses are not published.",
  },
};

const VULNERABILITY_PATTERNS = {
  sql_injection: {
    pattern: /(execute|query|cursor\.execute)\s*\(\s*["'].*%s.*["']|f["'].*SELECT.*\{/i,
    severity: "critical",
    title: "SQL built from string formatting",
    remediation:
      "Use parameterized queries (placeholders plus a separate values " +
      "argument) instead of formatting values into the SQL string.",
  },
  xss: {
    pattern: /(innerHTML|outerHTML|document\.write)\s*=/i,
    severity: "high",
    title: "Unescaped HTML sink",
    remediation:
      "Assign textContent, build nodes with createElement, or sanitize with " +
      "DOMPurify before writing HTML.",
  },
  // Not preceded by a dot or word char: regex.exec() and obj.eval() are
  // method calls, not the dangerous builtins.
  eval_usage: {
    pattern: new RegExp("(?<![.\\w])ev" + "al\\s*\\("),
    severity: "high",
    title: "Dynamic code evaluation",
    remediation:
      "Replace dynamic evaluation with a parser (JSON.parse, ast.literal_eval) " +
      "or an explicit lookup table.",
  },
  exec_usage: {
    pattern: new RegExp("(?<![.\\w])ex" + "ec\\s*\\("),
    severity: "high",
    title: "Dynamic code or command execution",
    remediation:
      "Avoid executing strings. For processes, call execFile/spawn with an " +
      "argument array and no shell.",
  },
  shell_injection: {
    pattern: /(os\.system|subprocess\.call|subprocess\.run|shell\s*[=:]\s*true)/i,
    severity: "high",
    title: "Shell command execution",
    remediation:
      "Pass an argument list with shell=False and never interpolate user " +
      "input into a command string.",
  },
  insecure_random: {
    pattern: /random\.(random|randint|choice)\s*\(/i,
    severity: "medium",
    title: "Non-cryptographic randomness",
    remediation:
      "For tokens, IDs, or anything security-relevant use the secrets module " +
      "(Python) or crypto.randomBytes / crypto.randomUUID (Node).",
  },
  hardcoded_secret: {
    pattern: /(secret|password|api_key|token)\s*=\s*["'][^"']+["']/i,
    severity: "medium",
    title: "Hardcoded secret value",
    remediation: ROTATE,
  },
  debug_mode: {
    pattern: /(debug\s*=\s*True|DEBUG\s*=\s*True)/,
    severity: "medium",
    title: "Debug mode enabled",
    remediation:
      "Drive debug mode from an environment variable that defaults to off in " +
      "production.",
  },
  cors_wildcard: {
    pattern: /(Access-Control-Allow-Origin|CORS).*\*/i,
    severity: "medium",
    title: "CORS allows any origin",
    remediation:
      "List the origins that need access instead of using *, especially on " +
      "endpoints that use cookies or auth headers.",
  },
  http_without_tls: {
    // XML/SVG namespace identifiers are URIs that are never fetched. The
    // trailing lookahead requires a dot in the host, so single-label names
    // like http://cipherguard-api:4000 (in-cluster services) are skipped.
    pattern:
      /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org|www\.sitemaps\.org|schemas\.|purl\.org|ns\.adobe\.com|xml\.apache\.org|java\.sun\.com|docbook\.org|www\.openarchives\.org|www\.inkscape\.org|sodipodi\.sourceforge\.net)(?=[A-Za-z0-9._~-]*\.)/i,
    severity: "low",
    title: "Plain HTTP URL",
    remediation: "Use https:// so the traffic is encrypted and authenticated.",
  },
};

module.exports = { SECRET_PATTERNS, VULNERABILITY_PATTERNS };
