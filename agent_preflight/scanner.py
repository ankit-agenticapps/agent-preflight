"""Read-only scanner for AI coding agent instruction and config files.

Nothing from the scanned repo is ever executed, imported or sourced. Files are
only opened as text/bytes and matched against patterns.
"""
import json
import os
import re
from urllib.parse import urlparse

MAX_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", "vendor"}
SEV_ORDER = {"high": 3, "medium": 2, "low": 1}

RULES = {
    "PF001": ("high", "hook-runs-command", "A hook runs a shell command on your machine without asking, every time the agent triggers it."),
    "PF002": ("high", "network-exfil", "Sends data to, or talks to, a remote host; this is how secrets leave your machine."),
    "PF003": ("high", "secret-access", "Touches credentials or API keys that an agent should never need to read or send."),
    "PF004": ("high", "remote-script-exec", "Downloads a script and runs it immediately, so whoever controls the URL controls your machine."),
    "PF005": ("high", "hidden-unicode", "Invisible characters can hide instructions that you cannot see but the agent can read."),
    "PF006": ("high", "vscode-autorun", "This VS Code task runs automatically the moment the folder is opened."),
    "PF101": ("medium", "override-user", "Tries to make the agent ignore you, hide actions from you, or skip your approval."),
    "PF102": ("medium", "permission-bypass", "Turns off or widens the agent's permission prompts, so it can act without asking you."),
    "PF103": ("medium", "mcp-unpinned", "Runs whatever the latest version of a package or remote server is, which can change under you."),
    "PF104": ("medium", "install-script", "Install-time scripts with network access run as soon as you install or open the project."),
    "PF105": ("medium", "encoded-blob", "Encoded content can hide commands or instructions from a quick read."),
    "PF201": ("low", "instruction-runs-commands", "The file tells the agent to run commands on its own at the start of a session."),
    "PF202": ("low", "external-urls", "Links to a site that is not on the well-known list; check you trust it."),
    "PF203": ("low", "unparseable-config", "The config could not be parsed as JSON, so it was only text-scanned and may hide things."),
}

START_EVENTS = {"SessionStart", "UserPromptSubmit", "Setup"}
MAX_SCRIPT_BYTES = 1024 * 1024
ALLOW_DOMAINS = ["github.com", "python.org", "npmjs.com", "pypi.org", "anthropic.com",
                 "openai.com", "microsoft.com", "google.com", "mozilla.org", "readthedocs.io",
                 "files.pythonhosted.org", "dot.net", "nodejs.org", "rustup.rs", "sh.rustup.rs",
                 "deno.land", "bun.sh", "astral.sh", "get.docker.com", "brew.sh",
                 "raw.githubusercontent.com", "registry.npmjs.org"]
# Official installer hosts: a piped install from these is MEDIUM in instruction prose, not HIGH.
# (raw.githubusercontent.com is deliberately absent: it hosts anyone's scripts.)
OFFICIAL_INSTALLERS = ["dot.net", "rustup.rs", "sh.rustup.rs", "astral.sh", "bun.sh", "deno.land",
                       "get.docker.com", "brew.sh", "nodejs.org"]

# ---------------------------------------------------------------- patterns
I = re.I
NET_TOOL = re.compile(r"\b(curl|wget|ncat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b", I)
NC_RAW = re.compile(r"\b(nc|ncat)\s+(-\w+\s+)*[\w.\-]+\s+\d{2,5}\b", I)
URL_OR_IP = re.compile(r"https?://[^\s'\"`)>\]]+|\b\d{1,3}(?:\.\d{1,3}){3}\b", I)
CODE_NET = re.compile(r"\bfetch\s*\(|requests\.(post|put|patch)\b|\bhttp\.client\b|urllib\.request\.urlopen|\bhttpx\.(post|put)\b", I)
EXFIL_HINT = re.compile(
    r"\$\(|`[^`]*`|\$\{?[A-Za-z_]+|base64|\bcat\s|<\s*~?/|\s-d\s|\s--data\S*|\s-F\s|\s--form\S*|\s-T\s|--upload-file|-X\s*(POST|PUT)|\bPOST\b|-Body\b|-InFile\b|\bopen\(", I)

PIPE_EXEC = re.compile(
    r"\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|perl|ruby|iex)\b"
    r"|\b(ba|z)?sh\s+<\(\s*(curl|wget)"
    r"|\biex\s*\(?\s*\(?\s*(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object)"
    r"|\|\s*iex\b", I)
DOWNLOAD_RUN = re.compile(r"\b(curl|wget)\b[^\n]*(&&|;)[^\n]*chmod\s+(\+x|[0-7]*7[0-7]*)\b", I)

SECRET_PATHS = re.compile(
    r"\.ssh\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials|\.config/gh\b|(?<![\w])\.netrc\b|\.npmrc\b"
    r"|(?<![\w/])\.env(?!\.(example|sample|template|dist)\b)(\.\w+)?\b|\bsecurity\s+find-(generic|internet)-password"
    r"|\bkeychain\b|\bprintenv\b|\bgh\s+auth\s+token\b|\.git-credentials|\.docker/config\.json|\.kube/config|\.pgpass"
    r"|\bos\.environ\b(?!\s*\[|\.get\b)|(^|[|;&]\s*)(env|set|export\s+-p)\s*(\||>|;|$)", I)
SECRET_NAMES = re.compile(
    r"\b(ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN"
    r"|NPM_TOKEN|GEMINI_API_KEY|GOOGLE_API_KEY|HF_TOKEN|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:API_KEY|SECRET|SECRET_KEY|TOKEN|PASSWORD))\b")
SECRET_ACTION = re.compile(r"\b(read|cat|send|print|echo|upload|post|copy|exfiltrate|paste|include)\b", I)
NEG_SECRET = re.compile(r"\b(never|don'?t|do\s+not|avoid|must\s+not|shouldn'?t|should\s+not|not)\b", I)
NEG_NET = re.compile(r"\b(never|don'?t|do\s+not|avoid|instead\s+of|rather\s+than)\b", I)
DESCRIPTIVE_MODAL = re.compile(r"\b(can|could|may|might|will|would|does|cannot|can'?t)\s+(also\s+)?$", I)
TEMPLATE_ENV = re.compile(r"\.env\.(example|sample|template|dist)\b", I)
EXISTS_CHECK = re.compile(r"\b(test\s+-[a-z]|\[\[?\s+-[a-z])\s+$", I)
# env-file loading / existence checks / VAR= assignments are not secret reads in commands
ENV_LOAD = re.compile(
    r"--env-file(-if-exists)?(=|\s+)\S+"
    r"|\bdotenvx?\b(\s+run)?(\s+(-f|-e|--env-file|--env)\s+\S+|\s+--[\w-]+(=\S+)?)*"
    r"|(?:\btest|\[\[?)\s+-[a-z]\s+\S+"
    r"|\b(echo|printf)\s+(\"[^\"$]*\"|'[^']*')"
    r"|\b[A-Za-z_][A-Za-z0-9_]*=(?=\S)", I)
DATA_FLAGS = re.compile(
    r"(?<![\w-])-d\b|(?<![\w-])-F\b|(?<![\w-])-T\b|(?i:--data\S*|--post-\S+|--form\S*|--upload-file|--body-\S+"
    r"|-X\s*(POST|PUT|PATCH)\b|-Body\b|-InFile\b)")

OVERRIDE = [
    re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|preceding)\s+(\w+\s+)?(instructions?|rules|prompts?|directions)", I),
    re.compile(r"ignore\s+all\s+(\w+\s+)?instructions", I),
    re.compile(r"(do\s+not|don'?t)\s+(tell|inform|notify|alert|mention(\s+this)?\s+to)\s+(the\s+)?(user|human|developer)", I),
    re.compile(r"\bwithout\s+(asking|telling|informing|notifying)\b", I),
    re.compile(r"\bsilently\b", I),
    re.compile(r"(don'?t|do\s+not|never)\s+ask\s+(for\s+)?(confirmation|permission|approval)", I),
    re.compile(r"\bnever\s+mention\b", I),
    re.compile(r"\bhide\s+this\b", I),
    re.compile(r"\byou\s+are\s+now\b", I),
    re.compile(r"\bsystem\s+override\b", I),
]
PERM_TEXT = re.compile(r"--dangerously-skip-permissions|--dangerously-bypass-approvals\S*|--yolo\b|bypassPermissions", I)
B64_USE = re.compile(r"base64\s+(-d|-D|--decode)\b|\batob\s*\(|frombase64string", I)
B64_BLOB = re.compile(r"[A-Za-z0-9+/=]{120,}")
START_RUN = re.compile(
    r"(at\s+the\s+start\s+of\s+(every|each)\s+(session|conversation|task)|before\s+anything\s+else"
    r"|first,?\s+(run|execute)\b|always\s+(run|execute)\b|at\s+session\s+start|on\s+startup,?\s+(run|execute))", I)
URL_RE = re.compile(r"https?://[^\s)>\]\"'`]+", I)
NETISH = re.compile(NET_TOOL.pattern + r"|\|\s*(sh|bash|zsh)\b|\bgit\s+clone\b", I)


# ---------------------------------------------------------------- helpers
def hidden_kind(ch, prev=""):
    cp = ord(ch)
    if cp == 0x200D and prev and ord(prev) >= 0x2190:
        return None  # emoji joiner
    if 0x200B <= cp <= 0x200F or cp == 0x2060 or cp == 0xFEFF:
        return "zero-width"
    if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
        return "bidi"
    if 0xE0000 <= cp <= 0xE007F:
        return "tag"
    return None


def show(s):
    out = []
    for i, ch in enumerate(s):
        out.append("<U+%04X>" % ord(ch) if hidden_kind(ch, s[i - 1] if i else "") else ch)
    return "".join(out)


def snippet(line, start=0):
    s = show(line.strip("\r\n"))
    s = s.strip()
    if len(s) > 160:
        a = max(0, show(line[:start]).lstrip().__len__() - 40) if start else 0
        s = s[a:a + 160]
        if a:
            s = "..." + s[3:]
        if len(s) == 160:
            s = s[:157] + "..."
    return s


def mk(rule, file, line, title, snip, severity=None, why=None):
    sev, _, w = RULES[rule]
    return {"rule": rule, "severity": severity or sev, "file": file, "line": line,
            "title": title, "snippet": snip, "why": why or w}


def host_allowed(host):
    host = (host or "").lower()
    if host.startswith("docs."):
        return True
    return any(host == d or host.endswith("." + d) for d in ALLOW_DOMAINS)


def url_hosts(s):
    hosts = []
    for m in URL_RE.finditer(s):
        try:
            hosts.append(urlparse(m.group(0)).hostname or "")
        except ValueError:
            hosts.append("")
    return hosts


def sends_data(text):
    """True if a curl/wget-style command carries data out (flags, or substitution inside a URL)."""
    m = NET_TOOL.search(text)
    seg = text[m.start():] if m else text
    seg = re.split(r"(?<!\|)\|(?!\|)|;|&&", seg, maxsplit=1)[0]  # only this command, not what it is piped into
    if DATA_FLAGS.search(seg):
        return True
    return any("$(" in u.group(0) or "`" in u.group(0) for u in URL_RE.finditer(seg))


def sentence_prefix(full, pos):
    start = 0
    for b in re.finditer(r"[.!?](?=\s)", full[:pos]):
        start = b.end()
    return full[start:pos]


def net_hit(text):
    """Return match for a network-exfil style construct, or None."""
    m = NET_TOOL.search(text)
    if m and URL_OR_IP.search(text):
        hosts = url_hosts(text)
        if hosts and all(host_allowed(h) for h in hosts) and not sends_data(text):
            return None
        return m
    m = NC_RAW.search(text) or CODE_NET.search(text)
    if m and (URL_OR_IP.search(text) or NC_RAW.search(text)):
        return m
    return None


def prose_secret_hit(text, ctx=""):
    """Secret reference in prose: only when an action verb is aimed at it, un-negated, in one sentence."""
    full = ctx + text
    off = len(ctx)
    for pat in (SECRET_PATHS, SECRET_NAMES):
        for sm in pat.finditer(text):
            pos = sm.start() + off
            pre = sentence_prefix(full, pos)
            if EXISTS_CHECK.search(pre):
                continue
            for v in SECRET_ACTION.finditer(pre):
                if pre[:v.start()].count("`") % 2:  # verb is inside a code span (a name, not an instruction)
                    continue
                span = pre[v.end():]
                if len(span) > 80 or TEMPLATE_ENV.search(span):
                    continue
                if NEG_SECRET.search(pre[:v.start()]) or DESCRIPTIVE_MODAL.search(pre[:v.start()]):
                    continue
                return sm
    return None


def secret_hit(text, mode, ctx=""):
    if mode == "text":
        return prose_secret_hit(text, ctx)
    cleaned = ENV_LOAD.sub(" ", text)
    return SECRET_PATHS.search(cleaned) or SECRET_NAMES.search(cleaned)


def negated(text, pos, ctx):
    return bool(NEG_NET.search(sentence_prefix(ctx + text, pos + len(ctx))))


def line_rules(text, file, lineno, mode, kind="instruction", ctx=""):
    """Apply per-line text rules. mode: 'cmd' (a command string) or 'text' (prose)."""
    out = []
    m = net_hit(text)
    if m and not (mode == "text" and negated(text, m.start(), ctx)):
        combo = bool(EXFIL_HINT.search(text))
        out.append(mk("PF002", file, lineno,
                      "Sends data out to the network" if combo else "Makes a network call",
                      snippet(text, m.start())))
    m = secret_hit(text, mode, ctx)
    if m:
        out.append(mk("PF003", file, lineno, "Reaches for secrets or credentials", snippet(text, m.start())))
    m = PIPE_EXEC.search(text) or DOWNLOAD_RUN.search(text)
    if m and not (mode == "text" and negated(text, m.start(), ctx)):
        hosts = url_hosts(text)
        official = mode == "text" and hosts and all(
            any(h == d or h.endswith("." + d) for d in OFFICIAL_INSTALLERS) for h in hosts)
        if official:
            out.append(mk("PF004", file, lineno, "Official installer piped/run from the web", snippet(text, m.start()),
                          severity="medium",
                          why="Runs a script straight from the web; this host is the tool's official installer, but pinning a checksum is safer."))
        else:
            out.append(mk("PF004", file, lineno, "Downloads and runs a script", snippet(text, m.start())))
    m = PERM_TEXT.search(text)
    if m:
        out.append(mk("PF102", file, lineno, "Bypasses agent permission checks", snippet(text, m.start())))
    m = B64_USE.search(text)
    if m:
        out.append(mk("PF105", file, lineno, "Decodes base64 content", snippet(text, m.start())))
    if mode == "text":
        for pat in OVERRIDE:
            m = pat.search(text)
            if m:
                out.append(mk("PF101", file, lineno, "Tries to override or hide things from the user",
                              snippet(text, m.start())))
                break
        for m in B64_BLOB.finditer(text):
            b = m.group(0)
            if re.search(r"[a-z]", b) and re.search(r"[A-Z]", b) and re.search(r"\d", b):
                out.append(mk("PF105", file, lineno, "Long base64-looking blob", snippet(text, m.start())))
                break
        m = START_RUN.search(text)
        if m:
            out.append(mk("PF201", file, lineno, "Tells the agent to run commands at the start", snippet(text, m.start())))
    return out


def find_line(raw_lines, needle):
    if not needle:
        return 1
    esc = json.dumps(needle)[1:-1]
    for cand in (esc, esc[:60], needle[:60]):
        if not cand:
            continue
        for i, l in enumerate(raw_lines):
            if cand in l:
                return i + 1
    return 1


def loads_lenient(raw):
    """json.loads, falling back to stripping // and /* */ comments and trailing commas (JSONC)."""
    try:
        return json.loads(raw)
    except ValueError:
        pass
    out, i, n, in_str = [], 0, len(raw), False
    while i < n:
        c = raw[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(raw[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif raw.startswith("//", i):
            while i < n and raw[i] != "\n":
                i += 1
            continue
        elif raw.startswith("/*", i):
            j = raw.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned)


def _cmd_string(d):
    c = d.get("command")
    if isinstance(c, list):
        c = " ".join(str(x) for x in c)
    if not isinstance(c, str):
        return None
    args = d.get("args")
    if isinstance(args, list):
        c += " " + " ".join(str(a) for a in args)
    return c


LIFECYCLE = {"postCreateCommand", "postStartCommand", "postAttachCommand", "onCreateCommand",
             "updateContentCommand", "initializeCommand"}


def _flat(v):
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [" ".join(str(x) for x in v)]
    if isinstance(v, dict):
        res = []
        for x in v.values():
            res.extend(_flat(x))
        return res
    return []


def iter_commands(node, key=None):
    if isinstance(node, dict):
        c = _cmd_string(node)
        if c:
            yield c
        for k, v in node.items():
            if k in LIFECYCLE or k == "apiKeyHelper":
                for s in _flat(v):
                    yield s
            elif k == "scripts" and isinstance(v, dict):
                for s in v.values():
                    if isinstance(s, str):
                        yield s
            elif isinstance(v, (dict, list)):
                yield from iter_commands(v, k)
    elif isinstance(node, list):
        for v in node:
            yield from iter_commands(v, key)


# ---------------------------------------------------------------- file-type rules
def hidden_unicode(text, file):
    findings, decoded_lines = [], []
    for n, line in enumerate(text.split("\n"), 1):
        kinds, tags, count = set(), [], 0
        for i, ch in enumerate(line):
            if n == 1 and i == 0 and ch == "﻿":
                continue
            k = hidden_kind(ch, line[i - 1] if i else "")
            if not k:
                continue
            count += 1
            kinds.add(k)
            if k == "tag":
                cp = ord(ch) - 0xE0000
                if 0x20 <= cp <= 0x7E:
                    tags.append(chr(cp))
                elif cp in (0x0A, 0x0D, 0x09):
                    tags.append(" ")
        if not count:
            continue
        if tags:
            payload = "".join(tags)
            snip = 'decoded: "%s"' % payload
            if len(snip) > 160:
                snip = snip[:157] + "..."
            findings.append(mk("PF005", file, n, "%d hidden Unicode tag characters carry a secret message" % count, snip))
            decoded_lines.append((n, payload))
        else:
            findings.append(mk("PF005", file, n,
                               "%d hidden %s character%s" % (count, "/".join(sorted(kinds)), "s" if count > 1 else ""),
                               snippet(line)))
    return findings, decoded_lines


def clean_hidden(s):
    return "".join(ch for i, ch in enumerate(s) if not hidden_kind(ch, s[i - 1] if i else ""))


def scan_instruction(text, file):
    findings, decoded = hidden_unicode(text, file)
    prev = ""
    for n, line in enumerate(text.split("\n"), 1):
        cl = clean_hidden(line)
        ctx = "" if re.match(r"\s*([-*+|#>]|\d+[.)])\s", cl) or not prev.strip() else prev.strip() + " "
        prev = cl
        findings.extend(line_rules(cl, file, n, "text", ctx=ctx))
        for m in URL_RE.finditer(line):
            host = urlparse(m.group(0)).hostname or ""
            if not host_allowed(host):
                findings.append(mk("PF202", file, n, "Link to %s" % (host or "unknown host"), snippet(line, m.start())))
    for n, payload in decoded:
        for f in line_rules(payload, file, n, "text"):
            f["snippet"] = ("hidden: " + f["snippet"])[:160]
            f["title"] = "Hidden text: " + f["title"][0].lower() + f["title"][1:]
            findings.append(f)
    return findings


def scan_text_config(text, file, extra=None):
    findings, decoded = hidden_unicode(text, file)
    for n, line in enumerate(text.split("\n"), 1):
        findings.extend(line_rules(clean_hidden(line), file, n, "cmd"))
    for n, payload in decoded:
        for f in line_rules(payload, file, n, "text"):
            f["snippet"] = ("hidden: " + f["snippet"])[:160]
            findings.append(f)
    return findings


def scan_json_config(text, file, base, root=None):
    findings, decoded = hidden_unicode(text, file)
    lines = text.split("\n")
    try:
        data = loads_lenient(text.lstrip("﻿"))
    except ValueError:
        findings.append(mk("PF203", file, 1, "Config is not valid JSON; fell back to text scan", snippet(lines[0] if lines else "")))
        return findings + scan_text_config(text, file)
    seen = set()
    # raw-text permission flags
    for n, line in enumerate(lines, 1):
        m = PERM_TEXT.search(clean_hidden(line))
        if m:
            findings.append(mk("PF102", file, n, "Bypasses agent permission checks", snippet(line, m.start())))
    # every command-like string
    for cmd in iter_commands(data):
        n = find_line(lines, cmd)
        for f in line_rules(cmd, file, n, "cmd"):
            if f["rule"] == "PF102":
                continue
            findings.append(f)
    if base.startswith("settings") and isinstance(data, dict):
        findings.extend(claude_settings(data, file, lines, root))
    if base in ("mcp.json",) or isinstance(data, dict) and ("mcpServers" in data or "servers" in data):
        findings.extend(mcp_rules(data, file, lines))
    if base == "tasks.json":
        findings.extend(vscode_tasks(data, file, lines))
    if base == "package.json" and isinstance(data, dict):
        findings.extend(lifecycle(data.get("scripts"), file, lines, ("preinstall", "install", "postinstall", "prepare")))
    if base == "devcontainer.json" and isinstance(data, dict):
        findings.extend(lifecycle(data, file, lines, ("postCreateCommand", "postStartCommand")))
    for n, payload in decoded:
        for f in line_rules(payload, file, n, "text"):
            f["snippet"] = ("hidden: " + f["snippet"])[:160]
            findings.append(f)
    return findings


SCRIPT_PATTERNS = [
    re.compile(r"\"?\$\{?CLAUDE_PROJECT_DIR\}?\"?/([^\s\"';|&)]+)"),
    re.compile(r"(?<![\w./$-])(\./[^\s\"';|&)]+|\.claude/[^\s\"';|&)]+|scripts/[^\s\"';|&)]+)"),
    re.compile(r"\b(?:node|bash|sh|zsh|python3?)\s+(?:-[\w-]+\s+)*([^\s\"';|&$~/-][^\s\"';|&]*)"),
]


def resolve_script(root, rel):
    """Return (relpath, text) for a regular, non-symlink, in-repo file <= 1 MB, else None."""
    if not root:
        return None
    rr = os.path.realpath(root)
    p = os.path.normpath(os.path.join(rr, rel.strip("\"'")))
    if not p.startswith(rr + os.sep):
        return None
    cur = rr
    for part in os.path.relpath(p, rr).split(os.sep):
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            return None
    try:
        if not os.path.isfile(p) or os.path.getsize(p) > MAX_SCRIPT_BYTES:
            return None
        text = read_text(p)
    except OSError:
        return None
    if text is None:
        return None
    return os.path.relpath(p, rr).replace(os.sep, "/"), text


def hook_scripts(root, cmd):
    seen, out = set(), []
    for pat in SCRIPT_PATTERNS:
        for m in pat.finditer(cmd):
            r = resolve_script(root, m.group(1))
            if r and r[0] not in seen:
                seen.add(r[0])
                out.append(r)
    return out


def scan_script(rel, text, called_by):
    findings, _ = hidden_unicode(text, rel)
    for n, line in enumerate(text.split("\n"), 1):
        st = line.strip()
        if (st.startswith("#") and not st.startswith("#!")) or st.startswith("//"):
            continue
        for f in line_rules(clean_hidden(line), rel, n, "cmd"):
            if f["rule"] in ("PF002", "PF003", "PF004"):
                findings.append(f)
    for f in findings:
        f["detail"] = called_by
    return findings


def claude_settings(data, file, lines, root=None):
    out = []
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                if not isinstance(e, dict):
                    continue
                inner = e.get("hooks") if isinstance(e.get("hooks"), list) else [e]
                for h in inner:
                    cmd = h.get("command") if isinstance(h, dict) else None
                    if not isinstance(cmd, str):
                        continue
                    ln = find_line(lines, cmd)
                    flags = []
                    if net_hit(cmd):
                        flags.append("reaches the network")
                    if secret_hit(cmd, "cmd"):
                        flags.append("touches secrets")
                    if PIPE_EXEC.search(cmd) or DOWNLOAD_RUN.search(cmd):
                        flags.append("runs a downloaded script")
                    details, any_hit = [], bool(flags)
                    sflags = []
                    for rel, stext in hook_scripts(root, cmd):
                        sf = scan_script(rel, stext, "called by %s:%d %s hook" % (file, ln, event))
                        out.extend(sf)
                        hit = {f["rule"] for f in sf} & {"PF002", "PF003", "PF004"}
                        for r_, w_ in (("PF002", "reaches the network"), ("PF003", "touches secrets"),
                                       ("PF004", "runs a downloaded script")):
                            if r_ in hit and w_ not in sflags:
                                sflags.append(w_)
                        d = "script: %s (%d lines)" % (rel, len(stext.splitlines()))
                        if not hit:
                            d += " \u2014 no network or secret access found in the script"
                        details.append(d)
                    start = event in START_EVENTS
                    if start:
                        title = "%s hook runs a command automatically when a session starts" % event
                    else:
                        title = "%s hook runs a command on every %s" % (event, event)
                    why = None
                    sev = "high" if start else "medium"
                    if flags or sflags:
                        sev = "high"
                        parts = list(flags) + ["its script " + w for w in sflags if w not in flags]
                        title = "%s hook runs a command%s and %s" % (
                            event, " automatically" if start else "", " and ".join(parts))
                        why = ("This hook runs by itself and %s; that is the pattern used to steal credentials."
                               % " and ".join(parts))
                    elif start:
                        why = "This command runs on your machine automatically as soon as a session starts, before you type anything."
                    else:
                        why = "This command runs on your machine every time the %s event fires, without asking." % event
                    f = mk("PF001", file, ln, title, snippet(cmd), severity=sev, why=why)
                    f["event"] = event
                    if details:
                        f["detail"] = "; ".join(details)
                    out.append(f)
    perms = data.get("permissions")
    if isinstance(perms, dict):
        allow = perms.get("allow")
        if isinstance(allow, list):
            for a in allow:
                if isinstance(a, str) and a.strip() in ("Bash", "Bash(*)", "Bash(*:*)"):
                    out.append(mk("PF102", file, find_line(lines, a), "Allows every shell command without asking", snippet(a)))
    return out


def mcp_rules(data, file, lines):
    out = []
    servers = None
    if isinstance(data, dict):
        servers = data.get("mcpServers") or data.get("servers")
    if not isinstance(servers, dict):
        return out
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        for k in ("autoApprove", "alwaysAllow"):
            v = cfg.get(k)
            if v is True or (isinstance(v, list) and v):
                out.append(mk("PF102", file, find_line(lines, k), "MCP server '%s' auto-approves its tools" % name,
                              snippet('"%s": %s' % (k, json.dumps(v)))))
        cmd = cfg.get("command")
        args = [str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []
        if isinstance(cmd, str):
            exe = os.path.basename(cmd).lower()
            if exe.endswith(".cmd") or exe.endswith(".exe"):
                exe = exe.rsplit(".", 1)[0]
            if exe in ("npx", "uvx", "pipx", "bunx"):
                rest = [a for a in args if not a.startswith("-")]
                if exe == "pipx" and rest and rest[0] == "run":
                    rest = rest[1:]
                pkg = rest[0] if rest else ""
                pinned = bool(re.search(r"(?<=.)@\d", pkg) or "==" in pkg)
                if pkg and not pinned:
                    out.append(mk("PF103", file, find_line(lines, name),
                                  "MCP server '%s' runs unpinned package %s" % (name, pkg),
                                  snippet("%s %s" % (cmd, " ".join(args)))))
        url = cfg.get("url") or cfg.get("serverUrl")
        if isinstance(url, str) and url.lower().startswith(("http://", "https://")):
            host = urlparse(url).hostname or ""
            if host not in ("localhost", "127.0.0.1", "::1"):
                out.append(mk("PF103", file, find_line(lines, url), "MCP server '%s' is a remote URL" % name, snippet(url)))
    return out


def vscode_tasks(data, file, lines):
    out = []
    tasks = data.get("tasks") if isinstance(data, dict) else None
    if isinstance(tasks, list):
        for t in tasks:
            if isinstance(t, dict) and isinstance(t.get("runOptions"), dict) \
                    and t["runOptions"].get("runOn") == "folderOpen":
                label = t.get("label", "task")
                cmd = _cmd_string(t) or ""
                out.append(mk("PF006", file, find_line(lines, "folderOpen"),
                              "Task '%s' runs when the folder is opened" % label, snippet(cmd or '"runOn": "folderOpen"')))
    return out


def lifecycle(d, file, lines, keys):
    out = []
    if not isinstance(d, dict):
        return out
    for k in keys:
        if k in d:
            for s in _flat(d[k]):
                if NETISH.search(s):
                    out.append(mk("PF104", file, find_line(lines, s), "%s uses the network or pipes to a shell" % k, snippet(s)))
    return out


# ---------------------------------------------------------------- discovery
ROOT_INSTRUCTION = ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
                    ".windsurfrules", ".github/copilot-instructions.md"]
INSTRUCTION_DIRS = [".cursor/rules", ".claude/commands", ".claude/agents", ".claude/skills"]
ROOT_CONFIG = [".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".cursor/mcp.json",
               ".vscode/settings.json", ".vscode/tasks.json", ".devcontainer/devcontainer.json",
               "package.json", ".codex/config.toml"]


def _ok_file(p):
    try:
        return os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) <= MAX_BYTES
    except OSError:
        return False


def discover(root):
    found = {}
    for rel in ROOT_INSTRUCTION:
        if _ok_file(os.path.join(root, rel)):
            found[rel] = "instruction"
    for d in INSTRUCTION_DIRS:
        base = os.path.join(root, d)
        if os.path.isdir(base) and not os.path.islink(base):
            for dp, dns, fns in os.walk(base):
                dns[:] = [x for x in dns if x not in SKIP_DIRS and not os.path.islink(os.path.join(dp, x))]
                for fn in fns:
                    p = os.path.join(dp, fn)
                    if _ok_file(p):
                        found[os.path.relpath(p, root).replace(os.sep, "/")] = "instruction"
    for dp, dns, fns in os.walk(root):
        depth = 0 if dp == root else os.path.relpath(dp, root).count(os.sep) + 1
        dns[:] = [x for x in dns if x not in SKIP_DIRS and not os.path.islink(os.path.join(dp, x))]
        if depth >= 4:
            dns[:] = []
        for fn in fns:
            if fn in ("CLAUDE.md", "AGENTS.md") and depth <= 4:
                p = os.path.join(dp, fn)
                if _ok_file(p):
                    found[os.path.relpath(p, root).replace(os.sep, "/")] = "instruction"
    for rel in ROOT_CONFIG:
        if _ok_file(os.path.join(root, rel)):
            found[rel] = "config"
    return found


def read_text(p):
    with open(p, "rb") as f:
        data = f.read()
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_repo(root):
    """Return (files_scanned, findings) for repo at root. Read-only."""
    root = os.path.abspath(root)
    files = discover(root)
    findings, scanned = [], 0
    for rel in sorted(files):
        try:
            text = read_text(os.path.join(root, rel))
        except OSError:
            continue
        if text is None:
            continue
        scanned += 1
        base = os.path.basename(rel)
        if files[rel] == "instruction":
            findings.extend(scan_instruction(text, rel))
        elif base.endswith(".toml"):
            findings.extend(scan_text_config(text, rel))
        else:
            findings.extend(scan_json_config(text, rel, base.replace("settings.local.json", "settings.json")
                                              if rel.startswith(".claude/") else base, root))
    uniq, seen = [], set()
    for f in findings:
        key = (f["rule"], f["file"], f["line"], f["snippet"], f["title"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    uniq.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"], f["rule"]))
    return scanned, uniq
