#!/usr/bin/env python3
"""Scanner LGPD: procura sinais de dados pessoais mal tratados em codigo-fonte.

Somente leitura. Nunca imprime nem grava o dado real: tudo que sai
(JSON, console, contexto) e mascarado, para que o proprio relatorio
nao vire um vazamento.

Uso:
    python agent/lgpd_scan.py --all --output findings.json
    python agent/lgpd_scan.py --files-from changed.txt --output findings.json
    python agent/lgpd_scan.py src/app.py src/models.py
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
MAX_LINE_CHARS = 2000
CONTEXT_LINES = 3
MAX_PER_RULE_PER_FILE = 20
MAX_TOTAL_FINDINGS = 500

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
    "__pycache__", ".next", "target", ".idea", ".vscode", ".tox",
}
SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".jar", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4",
    ".mov", ".exe", ".dll", ".so", ".class", ".pyc", ".lock", ".min.js",
    ".map", ".svg",
)
SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "composer.lock", "Pipfile.lock", "LICENSE", "LICENSE.md", "AUTHORS",
    "CODEOWNERS",
}
TEST_HINTS = {
    "test", "tests", "__tests__", "spec", "fixture", "fixtures", "mock",
    "mocks", "sample", "samples", "example", "examples", "seed", "seeds",
    "__snapshots__",
}

SEV_ORDER = {"baixo": 1, "medio": 2, "alto": 3}
DOWNGRADE = {"alto": "medio", "medio": "baixo", "baixo": "baixo"}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    lgpd: str
    fix: str


RULES = {
    "cpf": Rule(
        "cpf", "CPF no codigo", "alto",
        "Art. 5, I; art. 6, III (necessidade) e VII (seguranca); art. 46",
        "Remova o CPF do codigo-fonte. Use dados ficticios em testes e guarde "
        "dados reais apenas em banco com controle de acesso, criptografia e "
        "mascaramento na exibicao.",
    ),
    "rg": Rule(
        "rg", "RG no codigo", "alto",
        "Art. 5, I; art. 6, III e VII; art. 46",
        "Remova o documento do codigo e use dados ficticios em testes.",
    ),
    "cnpj": Rule(
        "cnpj", "CNPJ no codigo", "baixo",
        "Art. 5, I (so se identificar pessoa natural, como MEI ou empresario individual)",
        "CNPJ de empresa nao e dado pessoal, mas de MEI pode ser. Confirme de quem e.",
    ),
    "email": Rule(
        "email", "E-mail no codigo", "baixo",
        "Art. 5, I; art. 6, III",
        "Se for e-mail de pessoa real, remova do codigo. E-mails corporativos "
        "genericos (contato@, suporte@) costumam ser aceitaveis.",
    ),
    "telefone": Rule(
        "telefone", "Telefone no codigo", "medio",
        "Art. 5, I; art. 6, III e VII",
        "Remova o numero do codigo e use numeros ficticios em testes.",
    ),
    "cep": Rule(
        "cep", "CEP no codigo", "baixo",
        "Art. 5, I (quando combinado com outros dados que identifiquem a pessoa)",
        "Isolado costuma ser inofensivo. Veja se aparece junto de nome ou endereco completo.",
    ),
    "cartao": Rule(
        "cartao", "Numero de cartao (passa no teste de Luhn)", "alto",
        "Art. 6, VII; art. 46 (e normas do setor, como PCI DSS)",
        "Nunca armazene numero de cartao no codigo. Use tokenizacao do gateway de pagamento.",
    ),
    "nascimento": Rule(
        "nascimento", "Data de nascimento no codigo", "medio",
        "Art. 5, I; art. 6, III; art. 14 (se envolver criancas ou adolescentes)",
        "Use datas ficticias em testes. Em producao, colete so se for necessario.",
    ),
    "sensivel": Rule(
        "sensivel", "Nome de campo sugere dado pessoal sensivel", "medio",
        "Art. 5, II; art. 11",
        "Dados de saude, religiao, etnia, biometria e similares exigem base legal "
        "especifica e protecao reforcada. Confirme se o campo e realmente necessario "
        "e se ha criptografia e controle de acesso.",
    ),
    "log_pii": Rule(
        "log_pii", "Dado pessoal ou segredo indo para log/console", "alto",
        "Art. 6, III e VII; art. 46; art. 48 (se vazar)",
        "Nao registre CPF, e-mail, senha ou token em log. Registre apenas um "
        "identificador interno ou o dado mascarado.",
    ),
    "credencial": Rule(
        "credencial", "Senha, token ou chave fixa no codigo", "alto",
        "Art. 6, VII e VIII; art. 46",
        "Mova para variavel de ambiente ou cofre de segredos e revogue o valor "
        "atual, pois ele ja esta no historico do Git.",
    ),
    "hash_fraco": Rule(
        "hash_fraco", "MD5/SHA-1 usado perto de senha", "medio",
        "Art. 6, VII; art. 46",
        "Para senhas use bcrypt, scrypt ou Argon2, nunca MD5 ou SHA-1.",
    ),
    "url_pii": Rule(
        "url_pii", "Dado pessoal ou segredo na URL (query string)", "alto",
        "Art. 6, III e VII; art. 46",
        "URLs ficam em logs de servidor, proxy e historico do navegador. Envie "
        "esses dados no corpo da requisicao (POST) ou em cabecalho.",
    ),
}

# ----------------------------- validadores ---------------------------------


def valid_cpf(d: str) -> bool:
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        s = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        if (s * 10) % 11 % 10 != int(d[n]):
            return False
    return True


def valid_cnpj(d: str) -> bool:
    if len(d) != 14 or d == d[0] * 14:
        return False

    def dv(base: str) -> int:
        w = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        if len(base) == 13:
            w = [6] + w
        r = sum(int(x) * k for x, k in zip(base, w)) % 11
        return 0 if r < 2 else 11 - r

    return dv(d[:12]) == int(d[12]) and dv(d[:13]) == int(d[13])


def luhn(d: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ------------------------------ padroes ------------------------------------

CPF_RE = re.compile(r"(?<!\d)(\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)")
CNPJ_RE = re.compile(r"(?<!\d)(\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{14})(?!\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+55[\s.\-]?\(?\d{2}\)?[\s.\-]?9?\d{4}[\s.\-]?\d{4}"
    r"|\(\d{2}\)[\s.\-]?9?\d{4}[\s.\-]?\d{4}"
    r"|\d{2}\s9\d{4}-\d{4})(?!\d)"
)
CEP_RE = re.compile(r"(?<!\d)\d{5}-\d{3}(?!\d)")
CARD_RE = re.compile(r"(?<!\d)\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{1,7}(?!\d)")
DOB_RE = re.compile(
    r"(?i)(nascimento|data_nasc|birth|dob)\w*['\"]?\s*[:=]\s*['\"]?\d{1,4}[\-/]\d{1,2}[\-/]\d{1,4}"
)
RG_RE = re.compile(r"(?i)(?<![A-Za-z])rg(?![A-Za-z])['\"]?\s*[:=]\s*['\"]?[\d.\-xX]{7,12}")

SENSITIVE_RE = re.compile(
    r"(?i)(?<![A-Za-z])(diagnostico|diagnóstico|cid10|cid_10|doenca|doença|"
    r"prontuario|prontuário|laudo|religiao|religião|orientacao_sexual|"
    r"orientação_sexual|etnia|raca|raça|cor_pele|biometria|"
    r"impressao_digital|filiacao_sindical|filiação_sindical|"
    r"opiniao_politica|opinião_política|genetico|genético|saude|saúde)(?![A-Za-z])"
)
LOG_CALL_RE = re.compile(
    r"(?i)\b(print|println|printf|console\.(log|info|debug|warn|error)|logger\.\w+|"
    r"logging\.\w+|log\.\w+|System\.out\.print\w*|error_log|var_dump)\s*\("
)
PII_NAME_RE = re.compile(
    r"(?i)(?<![A-Za-z])(cpf|cnpj|rg|email|e-mail|senha|password|passwd|telefone|"
    r"phone|celular|nascimento|endereco|endereço|token|cartao|cartão|card_number)"
    r"(?![A-Za-z])"
)
CRED_RE = re.compile(
    r"(?i)(senha|password|passwd|secret|api[_\-]?key|token)['\"]?\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"
)
PLACEHOLDERS = (
    "changeme", "change_me", "xxxx", "****", "example", "exemplo", "placeholder",
    "your_", "seu_", "<", "${", "{{", "process.env", "getenv", "os.environ",
)
HASH_RE = re.compile(r"(?i)\b(md5|sha-?1)\b")
PASSWORD_WORD_RE = re.compile(r"(?i)(senha|password|passwd)")
URL_PII_RE = re.compile(
    r"(?i)https?://\S*[?&](cpf|email|senha|password|token|telefone|phone)="
)

IGNORED_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "localhost",
    "users.noreply.github.com", "email.com", "domain.com", "dominio.com.br",
    "exemplo.com", "exemplo.com.br",
}
IGNORED_EMAIL_TLDS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".local", ".test",
    ".invalid", ".example",
)


def email_ignored(addr: str) -> bool:
    local, _, domain = addr.lower().rpartition("@")
    if domain in IGNORED_EMAIL_DOMAINS or domain.endswith(IGNORED_EMAIL_TLDS):
        return True
    return local.startswith(("noreply", "no-reply", "donotreply"))


def detect(line: str) -> list[tuple[str, str]]:
    """Devolve lista de (id_da_regra, confianca) para uma linha."""
    hits: list[tuple[str, str]] = []

    for m in CPF_RE.finditer(line):
        raw = m.group(1)
        if valid_cpf(re.sub(r"\D", "", raw)):
            hits.append(("cpf", "alta" if "." in raw else "media"))

    for m in CNPJ_RE.finditer(line):
        raw = m.group(1)
        if valid_cnpj(re.sub(r"\D", "", raw)):
            hits.append(("cnpj", "alta" if "." in raw else "media"))

    for m in EMAIL_RE.finditer(line):
        if not email_ignored(m.group(0)):
            hits.append(("email", "media"))

    if PHONE_RE.search(line):
        hits.append(("telefone", "media"))
    if CEP_RE.search(line):
        hits.append(("cep", "media"))

    for m in CARD_RE.finditer(line):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn(digits) and not valid_cnpj(digits):
            hits.append(("cartao", "media"))

    if DOB_RE.search(line):
        hits.append(("nascimento", "media"))
    if RG_RE.search(line):
        hits.append(("rg", "media"))
    if SENSITIVE_RE.search(line):
        hits.append(("sensivel", "baixa"))

    if LOG_CALL_RE.search(line) and PII_NAME_RE.search(line):
        hits.append(("log_pii", "media"))

    for m in CRED_RE.finditer(line):
        value = m.group(2).lower()
        if not any(p in value for p in PLACEHOLDERS):
            hits.append(("credencial", "media"))

    if HASH_RE.search(line) and PASSWORD_WORD_RE.search(line):
        hits.append(("hash_fraco", "media"))
    if URL_PII_RE.search(line):
        hits.append(("url_pii", "alta"))

    return hits


# ------------------------------ mascaras -----------------------------------


def _mask_keep_last2(m: re.Match) -> str:
    s = m.group(0)
    total = sum(ch.isdigit() for ch in s)
    seen = 0
    out = []
    for ch in s:
        if ch.isdigit():
            seen += 1
            out.append(ch if seen > total - 2 else "*")
        else:
            out.append(ch)
    return "".join(out)


def _mask_email(m: re.Match) -> str:
    local, _, domain = m.group(0).partition("@")
    return f"{local[:1]}***@{domain}"


def _mask_all_digits(m: re.Match) -> str:
    return re.sub(r"\d", "*", m.group(0))


def mask_text(text: str) -> str:
    """Mascara qualquer dado pessoal reconhecivel (sem validar, para errar para o lado seguro)."""
    text = EMAIL_RE.sub(_mask_email, text)
    text = DOB_RE.sub(_mask_all_digits, text)
    text = RG_RE.sub(_mask_all_digits, text)
    text = CNPJ_RE.sub(_mask_keep_last2, text)
    text = CPF_RE.sub(_mask_keep_last2, text)
    text = PHONE_RE.sub(_mask_keep_last2, text)
    text = CARD_RE.sub(_mask_keep_last2, text)
    text = CEP_RE.sub(_mask_keep_last2, text)
    text = CRED_RE.sub(lambda m: f"{m.group(1)}=\"***\"", text)
    return text


# ------------------------------ varredura ----------------------------------


def is_test_path(rel: str) -> bool:
    parts = [p.lower() for p in rel.replace("\\", "/").split("/")]
    name = parts[-1]
    if any(p in TEST_HINTS for p in parts[:-1]):
        return True
    return (
        name.startswith("test_")
        or name.endswith(("_test.py", "_test.go"))
        or ".test." in name
        or ".spec." in name
    )


def should_skip(path: Path) -> bool:
    name = path.name
    return name in SKIP_NAMES or name.lower().endswith(SKIP_SUFFIXES)


def scan_file(path: Path, rel: str) -> list[dict]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        raw = path.read_bytes()
    except OSError:
        return []
    if b"\0" in raw[:4096]:
        return []

    lines = raw.decode("utf-8", errors="replace").splitlines()
    in_test = is_test_path(rel)
    per_rule: dict[str, int] = {}
    findings: list[dict] = []

    for i, line in enumerate(lines):
        if len(line) > MAX_LINE_CHARS:
            continue
        seen_on_line: set[str] = set()
        for rule_id, confidence in detect(line):
            if rule_id in seen_on_line:
                continue
            seen_on_line.add(rule_id)
            if per_rule.get(rule_id, 0) >= MAX_PER_RULE_PER_FILE:
                continue
            per_rule[rule_id] = per_rule.get(rule_id, 0) + 1

            rule = RULES[rule_id]
            severity = DOWNGRADE[rule.severity] if in_test else rule.severity
            lo = max(0, i - CONTEXT_LINES)
            hi = min(len(lines), i + CONTEXT_LINES + 1)
            context = "\n".join(
                f"{n + 1}: {mask_text(lines[n].strip()[:200])}" for n in range(lo, hi)
            )
            findings.append(
                {
                    "file": rel,
                    "line": i + 1,
                    "rule": rule.id,
                    "title": rule.title,
                    "severity": severity,
                    "confidence": confidence,
                    "in_test": in_test,
                    "lgpd": rule.lgpd,
                    "fix": rule.fix,
                    "snippet": mask_text(line.strip()[:200]),
                    "context": context,
                }
            )
    return findings


def collect_files(root: Path, args: argparse.Namespace) -> list[Path]:
    files: list[Path] = []
    if args.all:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                files.append(Path(dirpath) / fn)
    else:
        names = list(args.paths)
        if args.files_from:
            names += [
                ln.strip()
                for ln in Path(args.files_from).read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
        for n in names:
            p = (root / n).resolve()
            # nunca sai da raiz do repositorio
            if root.resolve() in p.parents and p.is_file():
                if not any(part in SKIP_DIRS for part in p.relative_to(root.resolve()).parts):
                    files.append(p)
    return [f for f in files if not should_skip(f)]


def main() -> int:
    ap = argparse.ArgumentParser(description="Scanner LGPD (somente leitura, saida mascarada)")
    ap.add_argument("paths", nargs="*", help="arquivos a analisar")
    ap.add_argument("--all", action="store_true", help="varrer o repositorio inteiro")
    ap.add_argument("--files-from", help="arquivo texto com um caminho por linha")
    ap.add_argument("--root", default=".", help="raiz do repositorio (padrao: .)")
    ap.add_argument("--output", default="findings.json")
    ap.add_argument("--fail-on", choices=["baixo", "medio", "alto"],
                    help="sai com codigo 1 se houver achado nessa severidade ou acima")
    args = ap.parse_args()

    if not (args.all or args.paths or args.files_from):
        ap.error("informe --all, --files-from ou arquivos")

    root = Path(args.root).resolve()
    files = collect_files(root, args)

    findings: list[dict] = []
    for f in sorted(files):
        findings.extend(scan_file(f, f.relative_to(root).as_posix()))

    findings.sort(key=lambda x: (-SEV_ORDER[x["severity"]], x["in_test"], x["file"], x["line"]))
    truncated = len(findings) > MAX_TOTAL_FINDINGS
    findings = findings[:MAX_TOTAL_FINDINGS]
    for n, item in enumerate(findings, 1):
        item["id"] = f"F{n:03d}"

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files_scanned": len(files),
        "truncated": truncated,
        "findings": findings,
    }
    Path(args.output).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in ("alto", "medio", "baixo")}
    print(
        f"Arquivos analisados: {len(files)} | achados: {len(findings)} "
        f"(alto: {counts['alto']}, medio: {counts['medio']}, baixo: {counts['baixo']})"
        + (" | lista truncada" if truncated else "")
    )

    if args.fail_on:
        limit = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER[x["severity"]] >= limit for x in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
