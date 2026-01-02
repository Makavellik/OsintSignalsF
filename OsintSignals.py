import time, statistics, hashlib, re, sys, signal
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, urlunparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm

# ----------------------------- CONFIG ---------------------------------
TIMING_SAMPLES = 9
JITTER_THRESHOLD = 0.40
RETRIES = 2
TIMEOUT = 10
console = Console()

# ----------------------------- SESSION --------------------------------
def build_session():
    # ------------------------------------------------------------------
    # 🧬 Perfiles de cliente (coherentes internamente)
    # ------------------------------------------------------------------
    PROFILES = [
        {
            "name": "desktop_chrome",
            "ua": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            ],
            "headers": {
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,image/avif,image/webp,*/*;q=0.8"
                ),
                "Upgrade-Insecure-Requests": "1",
            }
        },
        {
            "name": "desktop_firefox",
            "ua": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
                "Gecko/20100101 Firefox/124.0",
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) "
                "Gecko/20100101 Firefox/123.0",
            ],
            "headers": {
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,*/*;q=0.8"
                ),
            }
        },
        {
            "name": "mobile",
            "ua": [
                "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 "
                "Mobile/15E148 Safari/604.1",
            ],
            "headers": {
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,*/*;q=0.8"
                ),
            }
        },
        {
            "name": "tooling_legit",
            "ua": [
                "curl/8.5.0",
                "Wget/1.21.4",
            ],
            "headers": {
                "Accept": "*/*",
            }
        }
    ]

    # ------------------------------------------------------------------
    # 🎛️ Selección polimórfica 
    # ------------------------------------------------------------------
    seed = int(time.time() // 60)  # cambia aprox cada minuto
    profile = PROFILES[seed % len(PROFILES)]
    ua = profile["ua"][seed % len(profile["ua"])]

    # ------------------------------------------------------------------
    # 🛠️ Construcción de sesión
    # ------------------------------------------------------------------
    s = requests.Session()

    # --- Headers base universales (no sospechosos)
    base_headers = {
        "User-Agent": ua,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "DNT": "1",
    }

    # --- Merge seguro
    base_headers.update(profile.get("headers", {}))
    s.headers.update(base_headers)

    # ------------------------------------------------------------------
    # 🛡️ Resiliencia de red (no cambia semántica)
    # ------------------------------------------------------------------
    retry = Retry(
        total=RETRIES,
        connect=RETRIES,
        read=RETRIES,
        backoff_factor=0.3,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD", "OPTIONS", "POST"])
    )

    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=10,
        pool_maxsize=10
    )

    s.mount("http://", adapter)
    s.mount("https://", adapter)

    return s



# ----------------------------- UTILS ----------------------------------
def safe(fn, default=None):
    try:
        return fn()
    except Exception as e:
        return default

def hash_body(text):
    return hashlib.sha256(text.encode(errors="ignore")).hexdigest()

# ------------------------ HTTP SEMANTICS -------------------------------
def http_semantics(session, url):
    """
    Lectura semántica HTTP.
    Activo-quirúrgico, sin explotación.
    """

    responses = []
    errors = []

    # --- Lecturas repetidas controladas (consistencia real)
    for _ in range(3):
        try:
            responses.append(session.get(url, timeout=TIMEOUT))
        except Exception as e:
            errors.append(str(e))

    # Fallback seguro
    if not responses:
        raise RuntimeError("No HTTP responses obtained")

    r1 = responses[0]
    h = r1.headers

    # --- Hashes de cuerpo (deriva semántica)
    body_hashes = [hash_body(r.text) for r in responses]
    hash_change = len(set(body_hashes)) > 1

    # --- HEAD vs GET coherencia (activo legítimo)
    try:
        r_head = session.head(url, timeout=TIMEOUT)
        head_len = int(r_head.headers.get("Content-Length", -1))
        head_mismatch = head_len != -1 and abs(head_len - len(r1.text)) > 128
    except Exception:
        head_mismatch = False

    # --- Cache & validadores
    etag = h.get("ETag")
    cache_control = h.get("Cache-Control", "")
    vary = h.get("Vary", "")

    cache_signals = {
        "etag_present": bool(etag),
        "cache_control": cache_control,
        "vary_present": bool(vary),
        "cache_ambiguous": (
            "no-cache" not in cache_control.lower()
            and "no-store" not in cache_control.lower()
            and not etag
        )
    }

    # --- Coherencia de tipo de contenido
    content_type = h.get("Content-Type", "")
    semantic_mismatch = (
        "json" in content_type.lower()
        and not r1.text.strip().startswith(("{", "["))
    )

    # --- Retorno compatible + enriquecido
    return {
        "status": r1.status_code,
        "len": len(r1.text),
        "hash_change": hash_change,
        "etag": bool(etag),
        "cache": cache_control,

        # 🔬 Señales avanzadas (no rompen flujo)
        "head_mismatch": head_mismatch,
        "semantic_mismatch": semantic_mismatch,
        "cache_signals": cache_signals,
        "vary": vary,
        "errors": errors
    }, r1


# ------------------------ DOM PROFUNDO --------------------------------
def dom_deep(html):
    """
    Análisis DOM profundo con lectura semántica .
    Pasivo + activo ligero (lectura), sin ejecución.
    """

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return {
            "scripts": 0,
            "hidden_inputs": 0,
            "data_actions": 0,
            "js_network": False,
            "signals": ["html_parse_error"]
        }

    scripts = soup.find_all("script")
    hidden = soup.select("input[type=hidden]")
    actions = soup.find_all(attrs={"data-action": True})

    # --- JS inline real (no vacío / no loader)
    inline_js = [
        s.string for s in scripts
        if s.string and len(s.string.strip()) > 40
    ]

    # --- Red JS ampliada
    js_network = any(
        kw in js
        for js in inline_js
        for kw in (
            "fetch(", "axios", "XMLHttpRequest",
            "WebSocket", ".send(", "navigator.sendBeacon"
        )
    )

    # --- Señales SPA / frameworks
    framework_hints = {
        "react": bool(soup.find(attrs={"data-reactroot": True})) or "__REACT_DEVTOOLS_GLOBAL_HOOK__" in html,
        "vue": "data-v-" in html or "__VUE_DEVTOOLS_GLOBAL_HOOK__" in html,
        "angular": "ng-version" in html or "angular.module" in html,
        "next": "__NEXT_DATA__" in html
    }

    spa_detected = any(framework_hints.values())

    # --- Inputs ocultos con semántica sensible
    hidden_sensitive = [
        i.get("name","").lower()
        for i in hidden
        if any(k in (i.get("name","")+i.get("id","")).lower()
               for k in ("token", "csrf", "auth", "session", "state"))
    ]

    # --- Eventos activos inline (cliente reactivo)
    event_attrs = sum(
        1 for tag in soup.find_all()
        for attr in tag.attrs
        if attr.startswith("on")
    )

    # --- Scripts externos (posible backend split)
    external_scripts = [
        s.get("src") for s in scripts if s.get("src")
    ]

    # --- Señales finales interpretadas
    signals = []

    if js_network:
        signals.append("active_js_network")

    if spa_detected:
        signals.append("spa_frontend")

    if hidden_sensitive:
        signals.append("hidden_state_tokens")

    if event_attrs > 20:
        signals.append("high_client_interactivity")

    if len(external_scripts) > len(inline_js):
        signals.append("logic_externalized")

    # --- Retorno compatible + enriquecido
    return {
        "scripts": len(scripts),
        "hidden_inputs": len(hidden),
        "data_actions": len(actions),
        "js_network": js_network,

        # 🔬 Profundidad añadida (no rompe nada)
        "inline_js_blocks": len(inline_js),
        "external_scripts": len(external_scripts),
        "hidden_sensitive": hidden_sensitive,
        "event_handlers": event_attrs,
        "framework_hints": framework_hints,
        "signals": signals
    }


# ------------------------ TIMING DIFERENCIAL (ADVANCED) ---------------------------
def timing_diff(session, url):
    """
    Análisis temporal diferencial GET / HEAD / OPTIONS
    Lectura forense de backend sin agresividad.
    """

    def measure(method):
        timings = []
        for _ in range(TIMING_SAMPLES):
            try:
                t0 = time.time()
                session.request(method, url, timeout=TIMEOUT)
                dt = time.time() - t0

                # clamp suave anti-picos (ruido de red)
                if 0 < dt < TIMEOUT:
                    timings.append(dt)
            except Exception:
                continue
        return timings

    # --- Warm-up silencioso (reduce cold-start / cache miss)
    try:
        session.get(url, timeout=TIMEOUT)
    except Exception:
        pass

    g = measure("GET")
    h = measure("HEAD")
    o = measure("OPTIONS")

    # --- Fallback seguro
    if not g or not o:
        return {
            "get_avg": None,
            "head_avg": None,
            "opt_avg": None,
            "jitter": None,
            "jitter_high": False,
            "method_gap": False,
            "signals": ["insufficient_samples"]
        }

    get_avg = statistics.mean(g)
    opt_avg = statistics.mean(o)
    head_avg = statistics.mean(h) if h else 0

    jitter = statistics.pstdev(g) if len(g) > 1 else 0
    gap = abs(get_avg - opt_avg)

    # --- Lectura semántica
    signals = []

    if jitter > JITTER_THRESHOLD:
        signals.append("timing_instability")

    if gap > 0.6:
        signals.append("method_processing_gap")

    if head_avg and head_avg < get_avg * 0.5:
        signals.append("head_optimized")

    if opt_avg > get_avg * 1.3:
        signals.append("options_heavy_logic")

    if jitter < 0.15 and gap < 0.2:
        signals.append("uniform_backend_path")

    # --- Retorno compatible + enriquecido
    return {
        "get_avg": round(get_avg, 3),
        "head_avg": round(head_avg, 3),
        "opt_avg": round(opt_avg, 3),
        "jitter": round(jitter, 3),
        "jitter_high": jitter > JITTER_THRESHOLD,
        "method_gap": gap > 0.6,

        # 🔬 extras forenses (no rompen nada)
        "samples": {
            "get": len(g),
            "head": len(h),
            "options": len(o)
        },
        "signals": signals
    }

# ------------------------ SUPERFICIE BACKEND---------------------
def backend_surface(session, url):
    """
    Análisis de superficie backend:
    OPTIONS + validación pasiva-activa ligera (sin mutar estado).
    """

    signals = []
    methods = []
    unusual = []

    # --- OPTIONS primario
    try:
        opt = session.options(url, timeout=TIMEOUT)
        allow = opt.headers.get("Allow", "") or opt.headers.get("allow", "")
    except Exception:
        return {
            "methods": [],
            "unusual": [],
            "risk_profile": "unknown",
            "signals": ["options_unavailable"]
        }

    # --- Normalización
    methods = sorted({
        m.strip().upper()
        for m in allow.split(",")
        if m.strip()
    })

    # --- Clasificación semántica
    safe_methods = {"GET", "HEAD", "OPTIONS"}
    common_methods = {"POST", "PUT", "DELETE", "PATCH"}
    exotic_methods = {
        "TRACE", "CONNECT", "DEBUG", "PROPFIND",
        "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"
    }

    unusual = [m for m in methods if m not in safe_methods | common_methods]

    # --- Señales por exposición declarada
    if "TRACE" in methods:
        signals.append("trace_enabled")

    if {"PUT", "DELETE", "PATCH"} & set(methods):
        signals.append("state_changing_methods")

    if any(m in exotic_methods for m in methods):
        signals.append("exotic_methods_exposed")

    if not methods:
        signals.append("allow_header_empty")

    if "OPTIONS" not in methods:
        signals.append("options_not_advertised")

    # ------------------------------------------------------------------
    # 🔬 VALIDACIÓN ACTIVA LIGERA (SIN CAMBIOS DE ESTADO)
    # ------------------------------------------------------------------

    # 1️⃣ HEAD vs GET coherencia (misma ruta, sin cuerpo)
    try:
        r_head = session.head(url, timeout=TIMEOUT)
        r_get = session.get(url, timeout=TIMEOUT)
        if r_head.status_code != r_get.status_code:
            signals.append("method_status_divergence")
    except Exception:
        pass

    # 2️⃣ Method override pasivo (cabecera, sin mutar)
    try:
        r_override = session.post(
            url,
            headers={"X-HTTP-Method-Override": "DELETE"},
            timeout=TIMEOUT
        )
        if r_override.status_code not in (400, 405):
            signals.append("method_override_accepted")
    except Exception:
        pass

    # 3️⃣ Gateway / proxy fingerprint
    proxy_headers = ("Via", "X-Forwarded-For", "X-Proxy", "X-Gateway")
    try:
        if any(h in r_get.headers for h in proxy_headers):
            signals.append("gateway_or_proxy_detected")
    except Exception:
        pass

    # 4️⃣ Coherencia Allow vs realidad
    if "GET" not in methods and r_get.status_code < 400:
        signals.append("allow_mismatch_real_behavior")

    # ------------------------------------------------------------------
    # 🧠 PERFIL DE RIESGO (SEMÁNTICO)
    # ------------------------------------------------------------------
    if any(m in exotic_methods for m in methods) or "method_override_accepted" in signals:
        risk_profile = "elevated"
    elif any(m in common_methods for m in methods):
        risk_profile = "moderate"
    elif methods:
        risk_profile = "low"
    else:
        risk_profile = "unknown"

    # --- Retorno compatible + más profundo
    return {
        "methods": methods,
        "unusual": unusual,
        "risk_profile": risk_profile,
        "signals": signals
    }



# ------------------------ SCORING (ADVANCED) ----------------------------
def score(sig):
    """
    Scoring heurístico forense.
    Prioriza correlaciones reales, no flags aislados.
    """

    s = 0

    # --- HTTP semantics
    if sig["http"].get("hash_change"):
        s += 3

    if sig["http"].get("etag"):
        s += 1  # cache inteligente → posible A/B o personalización

    # --- Timing
    timing = sig.get("timing", {})
    if timing.get("jitter_high"):
        s += 2

    if timing.get("method_gap"):
        s += 2

    if "method_processing_gap" in timing.get("signals", []):
        s += 2

    # --- DOM profundo
    dom = sig.get("dom", {})

    if dom.get("hidden_inputs", 0) > 0:
        s += 2

    if dom.get("hidden_sensitive"):
        s += 3  # tokens / estado interno real

    if dom.get("js_network"):
        s += 2

    if "spa_frontend" in dom.get("signals", []):
        s += 1

    # --- Superficie backend
    surface = sig.get("surface", {})

    if surface.get("unusual"):
        s += 3

    if surface.get("risk_profile") == "elevated":
        s += 2
    elif surface.get("risk_profile") == "moderate":
        s += 1

    # --- Bonus por correlación (la magia real)
    if (
        sig["http"].get("hash_change")
        and dom.get("js_network")
        and timing.get("method_gap")
    ):
        s += 3  # frontend + backend + tiempo alineados

    return s

# ------------------------ INTERPRETACIÓN (ADVANCED) ----------------------
def insights(sig):
    """
    Interpretación cognitiva de señales.
    Traduce heurística → significado operacional.
    """

    out = []

    http = sig.get("http", {})
    timing = sig.get("timing", {})
    dom = sig.get("dom", {})
    surface = sig.get("surface", {})

    # --- HTTP
    if http.get("hash_change"):
        out.append(
            "Respuesta no determinística → estado interno, personalización o A/B testing activo."
        )

    if http.get("etag"):
        out.append(
            "ETag presente → cache inteligente o backend consciente del cliente."
        )

    # --- Timing
    if timing.get("method_gap"):
        out.append(
            "Diferencias temporales por método → rutas backend distintas o middleware condicional."
        )

    if "method_processing_gap" in timing.get("signals", []):
        out.append(
            "GET y OPTIONS no recorren el mismo flujo → posible control por rol, WAF o gateway."
        )

    if timing.get("jitter_high"):
        out.append(
            "Inestabilidad temporal → colas, balanceadores o servicios elásticos."
        )

    # --- DOM
    if dom.get("hidden_sensitive"):
        out.append(
            "Tokens ocultos detectados → flujos de estado multi-paso o validaciones internas."
        )

    if dom.get("js_network"):
        out.append(
            "Frontend genera tráfico activo → APIs no evidentes desde la UI."
        )

    if "spa_frontend" in dom.get("signals", []):
        out.append(
            "Arquitectura SPA → superficie real en APIs, no en rutas HTML clásicas."
        )

    # --- Superficie backend
    if surface.get("unusual"):
        out.append(
            "Métodos HTTP poco comunes expuestos → desalineación entre diseño y despliegue."
        )

    if surface.get("risk_profile") == "elevated":
        out.append(
            "Superficie backend elevada → priorizar revisión manual y correlación."
        )

    # --- Insight de alto nivel (correlación)
    if (
        http.get("hash_change")
        and dom.get("js_network")
        and timing.get("method_gap")
    ):
        out.append(
            "Frontend reactivo + backend condicional → alta probabilidad de lógica no documentada."
        )

    if not out:
        out.append(
            "Superficie homogénea → backend plano o bien encapsulado."
        )

    return out


# ------------------------ ORQUESTADOR ---------------------------------
def scan(url):
    session = build_session()
    phases = {}
    warnings = []

    # --- HTTP semantics
    t0 = time.time()
    try:
        http, resp = http_semantics(session, url)
    except Exception as e:
        http, resp = {}, None
        warnings.append(f"http_semantics_error: {type(e).__name__}")
    phases["http"] = round(time.time() - t0, 3)

    # --- DOM profundo
    t0 = time.time()
    try:
        dom = dom_deep(resp.text if resp else "")
    except Exception as e:
        dom = {}
        warnings.append(f"dom_error: {type(e).__name__}")
    phases["dom"] = round(time.time() - t0, 3)

    # --- Timing
    t0 = time.time()
    try:
        timing = timing_diff(session, url)
    except Exception as e:
        timing = {}
        warnings.append(f"timing_error: {type(e).__name__}")
    phases["timing"] = round(time.time() - t0, 3)

    # --- Superficie backend
    t0 = time.time()
    try:
        surface = backend_surface(session, url)
    except Exception as e:
        surface = {}
        warnings.append(f"surface_error: {type(e).__name__}")
    phases["surface"] = round(time.time() - t0, 3)

    sig = {
        "http": http,
        "dom": dom,
        "timing": timing,
        "surface": surface
    }

    return {
        "url": url,
        "signals": sig,
        "priority": score(sig),
        "insights": insights(sig),
        "meta": {
            "phases_sec": phases,
            "warnings": warnings
        }
    }


# ------------------------ VISUAL NEON ---------------------------------
def render(report):
    console.print(Panel(
        Text("OsintSignalsF — NEON SURGICAL MODE", style="bold neon_magenta"),
        border_style="bright_cyan"
    ))

    table = Table(
        title="🧬 Señales Backend & Forenses",
        header_style="bold bright_yellow",
        show_lines=True
    )
    table.add_column("Capa", style="bold bright_blue")
    table.add_column("Detalle", style="bright_green")

    color_map = {
        "http": "bright_cyan",
        "dom": "bright_magenta",
        "timing": "bright_yellow",
        "surface": "bright_red"
    }

    for k, v in report["signals"].items():
        style = color_map.get(k, "white")
        detail = str(v)
        if len(detail) > 400:
            detail = detail[:400] + "…"
        table.add_row(k, Text(detail, style=style))

    console.print(table)

    # --- Interpretación
    insights_text = "\n".join(f"• {i}" for i in report["insights"]) or "Sin hallazgos críticos"
    console.print(Panel(
        insights_text,
        title="🧠 Interpretación Cognitiva",
        border_style="bright_magenta"
    ))

    # --- Prioridad
    prio_style = "bright_green"
    if report["priority"] >= 10:
        prio_style = "bright_red"
    elif report["priority"] >= 6:
        prio_style = "bright_yellow"

    console.print(Panel(
        Text(f"PRIORITY SCORE: {report['priority']}", style=f"bold {prio_style}"),
        title="🔥 Prioridad",
        border_style=prio_style
    ))

    # --- Meta
    meta = report.get("meta", {})
    if meta:
        meta_lines = []
        if meta.get("phases_sec"):
            meta_lines.append("⏱️ Fases (s): " + str(meta["phases_sec"]))
        if meta.get("warnings"):
            meta_lines.append("⚠️ Avisos: " + ", ".join(meta["warnings"]))

        console.print(Panel(
            "\n".join(meta_lines),
            title="🧪 Meta & Telemetría",
            border_style="bright_blue"
        ))

# ----------------------------- CLI (NEON ALCHEMICAL MODE) -----------------------------
def graceful_exit(signum, frame):
    console.print("\n🛑 Interrupción detectada. Cerrando de forma segura…",
                  style="bold bright_red")
    sys.exit(130)

signal.signal(signal.SIGINT, graceful_exit)

def neon_banner():
    title = Text("OSINTSIGNALSF", style="bold neon_magenta")
    subtitle = Text(
        "NEON ALCHEMICAL MODE — Surgical Intelligence Engine — ByMakaveli New Era",
        style="bright_cyan"
    )
    body = Align.center(title + "\n" + subtitle)
    console.print(Panel(body, border_style="bright_magenta"))

def validate_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError("La URL debe ser una cadena de texto")

    # --- Limpieza básica
    url = url.strip()
    if not url:
        raise ValueError("URL vacía")

    # --- Esquema obligatorio
    if not url.startswith(("http://", "https://")):
        raise ValueError("Debe iniciar con http:// o https://")

    # --- Parseo estructural
    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Estructura de URL inválida")

    # --- Host válido (evita cosas raras tipo http://)
    host = parsed.hostname
    if not host:
        raise ValueError("Host no detectable en la URL")

    # --- Caracteres sospechosos (control, espacios)
    if re.search(r"[\s\x00-\x1f\x7f]", url):
        raise ValueError("La URL contiene caracteres no válidos")

    # --- Puerto inválido
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Puerto fuera de rango válido")

    # --- Normalización segura (sin cambiar significado)
    normalized = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        ""   # eliminamos fragment (#) → no aporta a backend
    ))

    return normalized


if __name__ == "__main__":
    neon_banner()

    while True:
        # ------------------------------------------------------------
        # INPUT GUIADO + VALIDACIÓN 
        # ------------------------------------------------------------
        try:
            target = Prompt.ask(
                "[bright_green]Target (scope autorizado)",
                default="https://example.com"
            )
            target = validate_url(target)
        except ValueError as e:
            console.print(
                Panel(
                    f"❌ Error de entrada:\n{e}",
                    title="INPUT ERROR",
                    border_style="bright_red"
                )
            )
            if not Confirm.ask("¿Deseas intentar nuevamente?", default=True):
                console.print("👋 Saliendo de forma segura.", style="bright_yellow")
                break
            continue

        # ------------------------------------------------------------
        # CONFIRMACIÓN ÉTICA
        # ------------------------------------------------------------
        if not Confirm.ask(
            "[bright_yellow]¿Confirmas que este target está dentro de tu scope autorizado?",
            default=False
        ):
            console.print("🚫 Operación cancelada por el usuario.", style="bold yellow")
            if Confirm.ask("¿Deseas analizar otro target?", default=True):
                continue
            break

        console.print(
            Panel(
                Text(
                    "🧠 Iniciando análisis quirúrgico pasivo-activo\n"
                    "• Sin mutar estado\n"
                    "• Sin explotación\n"
                    "• Lectura cognitiva de señales",
                    style="bright_green"
                ),
                title="⚡ Protocolo Activo",
                border_style="bright_cyan"
            )
        )

        # ------------------------------------------------------------
        # EJECUCIÓN CONTROLADA 
        # ------------------------------------------------------------
        rep = None
        try:
            with Progress(
                SpinnerColumn(style="bright_magenta"),
                TextColumn("[bold bright_cyan]{task.description}"),
                BarColumn(bar_width=30),
                transient=True
            ) as progress:
                task = progress.add_task(
                    "Escaneando superficie cognitiva…", total=100
                )

                for step in (15, 35, 55):
                    time.sleep(0.15)
                    progress.update(task, advance=step)

                rep = scan(target)
                progress.update(task, completed=100)

        except KeyboardInterrupt:
            console.print(
                Panel(
                    "⛔ Escaneo interrumpido por el operador.",
                    title="INTERRUPCIÓN",
                    border_style="bright_yellow"
                )
            )
        except Exception as e:
            console.print(
                Panel(
                    f"💥 Error durante el escaneo:\n{type(e).__name__}: {e}",
                    title="ERROR CONTROLADO",
                    border_style="bright_red"
                )
            )

        # ------------------------------------------------------------
        # RENDER (SOLO SI HUBO RESULTADO)
        # ------------------------------------------------------------
        if rep:
            console.print(
                "\n✨ Análisis completado. Revelando señales…\n",
                style="bold bright_magenta"
            )
            render(rep)

            console.print(
                Panel(
                    Text(
                        "🧬 Proceso finalizado correctamente\n"
                        "Recuerda: la verdadera fuerza está en interpretar, no en atacar.\n"
                        "— ByMakaveli",
                        style="bright_green"
                    ),
                    border_style="bright_green"
                )
            )

        # ------------------------------------------------------------
        # DECISIÓN FINAL DEL OPERADOR
        # ------------------------------------------------------------
        if not Confirm.ask(
            "[bright_cyan]¿Deseas analizar otro objetivo?",
            default=True
        ):
            console.print(
                Panel(
                    "👋 Cerrando sesión de forma segura.\nGracias por usar OsintSignalsF.",
                    border_style="bright_magenta"
                )
            )
            break
