import time, statistics, hashlib, re, sys, signal, random
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
    """
    Construye una sesión HTTP consistente para observación.

    Objetivos:
        • Cliente estable.
        • Headers coherentes.
        • Reintentos controlados.
        • Lectura reproducible.

    No modifica el comportamiento del escáner.
    Solo mejora la calidad de las observaciones.
    """

    # ---------------------------------------------------------
    # Perfiles simples y coherentes
    # ---------------------------------------------------------
    profiles = [
        {
            "name": "chrome",
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        },
        {
            "name": "firefox",
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
                "Gecko/20100101 Firefox/124.0"
            ),
        },
        {
            "name": "mobile",
            "user_agent": (
                "Mozilla/5.0 (Linux; Android 14) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/123.0 Mobile Safari/537.36"
            ),
        },
    ]

    # ---------------------------------------------------------
    # Rotación ligera
    # ---------------------------------------------------------
    profile = random.choice(profiles)

    session = requests.Session()

    session.headers.update({

        "User-Agent": profile["user_agent"],

        "Accept": (
            "text/html,"
            "application/xhtml+xml,"
            "application/xml;q=0.9,"
            "image/avif,"
            "image/webp,"
            "*/*;q=0.8"
        ),

        "Accept-Language": "en-US,en;q=0.9",

        "Accept-Encoding": "gzip, deflate, br",

        "Connection": "keep-alive",

        "Upgrade-Insecure-Requests": "1",

        "DNT": "1",

    })

    # ---------------------------------------------------------
    # Adaptador resiliente
    # ---------------------------------------------------------
    retry = Retry(

        total=RETRIES,

        connect=RETRIES,

        read=RETRIES,

        backoff_factor=0.35,

        status_forcelist=(
            429,
            500,
            502,
            503,
            504,
        ),

        allowed_methods=frozenset({
            "GET",
            "HEAD",
            "OPTIONS",
            "POST",
        }),

        raise_on_status=False,

    )

    adapter = HTTPAdapter(

        max_retries=retry,

        pool_connections=10,

        pool_maxsize=10,

    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # ---------------------------------------------------------
    # Metadatos útiles para el resto del motor
    # ---------------------------------------------------------
    session.profile = profile["name"]

    session.created_at = time.time()

    return session



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
    Lectura semántica HTTP avanzada.

    Filosofía:
    - Activo quirúrgico
    - Pasivo contextual
    - Sin explotación
    - Orientado a observación, coherencia y comportamiento

    Analiza:
    - estabilidad de respuesta
    - identidad temporal
    - consistencia semántica
    - cache behavior
    - fingerprints operativos
    """

    responses = []
    errors = []

    timestamps = []

    # =====================================================
    # OBSERVACIÓN REPETIDA CONTROLADA
    # =====================================================

    for _ in range(3):
        try:
            start = time.time()

            response = session.get(
                url,
                timeout=TIMEOUT
            )

            elapsed = int(
                (time.time() - start) * 1000
            )

            responses.append(response)
            timestamps.append(elapsed)

        except Exception as e:
            errors.append(str(e))


    if not responses:
        raise RuntimeError(
            "No HTTP responses obtained"
        )


    r1 = responses[0]
    h = r1.headers


    # =====================================================
    # DERIVA SEMÁNTICA DEL CONTENIDO
    # =====================================================

    body_hashes = [
        hash_body(r.text)
        for r in responses
    ]

    hash_change = (
        len(set(body_hashes)) > 1
    )


    body_sizes = [
        len(r.text)
        for r in responses
    ]


    size_variation = (
        max(body_sizes) -
        min(body_sizes)
    )


    # =====================================================
    # LATENCIA Y COMPORTAMIENTO
    # =====================================================

    avg_latency = (
        sum(timestamps) / len(timestamps)
        if timestamps
        else None
    )


    latency_variance = (
        max(timestamps) -
        min(timestamps)
        if timestamps
        else 0
    )


    # =====================================================
    # HEAD VS GET
    # =====================================================

    try:

        r_head = session.head(
            url,
            timeout=TIMEOUT
        )

        head_len = int(
            r_head.headers.get(
                "Content-Length",
                -1
            )
        )

        head_mismatch = (
            head_len != -1
            and abs(head_len - len(r1.text)) > 128
        )


    except Exception:

        head_mismatch = False



    # =====================================================
    # CACHE / DELIVERY SEMANTICS
    # =====================================================

    etag = h.get("ETag")

    cache_control = (
        h.get(
            "Cache-Control",
            ""
        )
    )

    vary = (
        h.get(
            "Vary",
            ""
        )
    )


    age = h.get("Age")

    cache_signals = {

        "etag_present":
            bool(etag),

        "cache_control":
            cache_control,

        "vary_present":
            bool(vary),

        "age_present":
            bool(age),

        "cdn_cache_hint":
            bool(age),

        "cache_ambiguous":
            (
                "no-cache" not in cache_control.lower()
                and
                "no-store" not in cache_control.lower()
                and
                not etag
            )
    }



    # =====================================================
    # COHERENCIA DE CONTENIDO
    # =====================================================

    content_type = (
        h.get(
            "Content-Type",
            ""
        )
    )


    text_sample = (
        r1.text.strip()[:50]
    )


    semantic_mismatch = (

        "json" in content_type.lower()

        and

        not text_sample.startswith(
            (
                "{",
                "["
            )
        )
    )


    # =====================================================
    # IDENTIDAD OPERATIVA
    # =====================================================

    server = h.get(
        "Server"
    )

    powered = h.get(
        "X-Powered-By"
    )


    exposure_signals = {

        "server_visible":
            bool(server),

        "framework_visible":
            bool(powered),

        "technology_disclosure":
            bool(
                server
                or powered
            )

    }



    # =====================================================
    # LECTURA INVERSA
    # =====================================================

    behavioral = {

        "dynamic_content":
            hash_change,

        "unstable_size":
            size_variation > 512,

        "slow_backend":
            avg_latency is not None
            and avg_latency > 2000,

        "response_variance":
            latency_variance > 500,

        "possible_edge_layer":
            bool(age)
            or bool(vary)

    }



    # =====================================================
    # RETORNO COMPATIBLE
    # =====================================================

    return {

        # originales
        "status":
            r1.status_code,

        "len":
            len(r1.text),

        "hash_change":
            hash_change,

        "etag":
            bool(etag),

        "cache":
            cache_control,


        # existentes enriquecidos

        "head_mismatch":
            head_mismatch,

        "semantic_mismatch":
            semantic_mismatch,

        "cache_signals":
            cache_signals,

        "vary":
            vary,

        "errors":
            errors,


        # nuevas capas SOC

        "behavior":

            behavioral,


        "performance":

            {
                "samples":
                    len(responses),

                "latencies_ms":
                    timestamps,

                "average_ms":
                    avg_latency,

                "variance_ms":
                    latency_variance
            },


        "delivery_identity":

            exposure_signals,


        "metadata":

            {
                "body_hashes":
                    body_hashes,

                "size_variation":
                    size_variation,

                "content_type":
                    content_type,

                "age_header":
                    age
            }

    }, r1


# ------------------------ DOM PROFUNDO --------------------------------
def dom_deep(html):
    """
    Análisis DOM profundo con lectura semántica avanzada.

    Filosofía:
    - Pasivo
    - Lectura estructural
    - Sin ejecución JavaScript
    - Sin interacción destructiva

    Observa:
    - arquitectura frontend
    - exposición de lógica
    - estado cliente
    - comunicación web
    - madurez tecnológica
    """

    try:
        soup = BeautifulSoup(
            html,
            "html.parser"
        )

    except Exception:

        return {
            "scripts": 0,
            "hidden_inputs": 0,
            "data_actions": 0,
            "js_network": False,
            "signals": [
                "html_parse_error"
            ]
        }


    # =====================================================
    # ELEMENTOS BASE
    # =====================================================

    scripts = soup.find_all(
        "script"
    )

    hidden = soup.select(
        "input[type=hidden]"
    )

    actions = soup.find_all(
        attrs={
            "data-action": True
        }
    )


    forms = soup.find_all(
        "form"
    )


    links = soup.find_all(
        "a",
        href=True
    )


    # =====================================================
    # JAVASCRIPT REAL
    # =====================================================

    inline_js = [

        s.string

        for s in scripts

        if s.string
        and len(s.string.strip()) > 40

    ]


    external_scripts = [

        s.get("src")

        for s in scripts

        if s.get("src")

    ]


    # =====================================================
    # COMUNICACIÓN CLIENTE ↔ SERVIDOR
    # =====================================================

    network_patterns = (

        "fetch(",
        "axios",
        "XMLHttpRequest",
        "WebSocket",
        ".send(",
        "navigator.sendBeacon",
        "graphql",
        "/api/",
        "socket.io"
    )


    js_network = any(

        pattern in js

        for js in inline_js

        for pattern in network_patterns

    )


    # =====================================================
    # FRAMEWORK INTELLIGENCE
    # =====================================================

    framework_hints = {

        "react":

            bool(
                soup.find(
                    attrs={
                        "data-reactroot": True
                    }
                )
            )

            or

            "__REACT_DEVTOOLS_GLOBAL_HOOK__"
            in html,


        "vue":

            "data-v-" in html

            or

            "__VUE_DEVTOOLS_GLOBAL_HOOK__"
            in html,


        "angular":

            "ng-version" in html

            or

            "angular.module"
            in html,


        "next":

            "__NEXT_DATA__"
            in html,


        "svelte":

            "svelte"
            in html.lower()

    }


    spa_detected = any(
        framework_hints.values()
    )


    # =====================================================
    # ESTADO OCULTO
    # =====================================================

    hidden_sensitive = [

        i.get("name","").lower()

        for i in hidden

        if any(

            key in (

                i.get("name","")
                +
                i.get("id","")

            ).lower()

            for key in (

                "token",
                "csrf",
                "auth",
                "session",
                "state",
                "nonce"

            )

        )

    ]


    # =====================================================
    # INTERACTIVIDAD CLIENTE
    # =====================================================

    event_attrs = sum(

        1

        for tag in soup.find_all()

        for attr in tag.attrs

        if attr.startswith("on")

    )


    # =====================================================
    # RECURSOS EXTERNOS
    # =====================================================

    external_domains = []

    for src in external_scripts:

        if src:

            external_domains.append(
                src.split("/")[2]
                if "//" in src
                else src
            )


    # =====================================================
    # DENSIDAD FRONTEND
    # =====================================================

    dom_complexity = {

        "html_size":

            len(html),


        "tag_count":

            len(
                soup.find_all()
            ),


        "script_ratio":

            len(scripts)
            /
            max(
                len(soup.find_all()),
                1
            )

    }



    # =====================================================
    # SEÑALES INTERPRETADAS
    # =====================================================

    signals = []


    if js_network:
        signals.append(
            "active_js_network"
        )


    if spa_detected:
        signals.append(
            "spa_frontend"
        )


    if hidden_sensitive:
        signals.append(
            "hidden_state_tokens"
        )


    if event_attrs > 20:
        signals.append(
            "high_client_interactivity"
        )


    if len(external_scripts) > len(inline_js):
        signals.append(
            "logic_externalized"
        )


    if len(forms) > 5:
        signals.append(
            "form_heavy_application"
        )


    if len(external_domains) > 5:
        signals.append(
            "third_party_dependency_heavy"
        )



    # =====================================================
    # LECTURA INVERSA
    # =====================================================

    architecture = {

        "client_heavy":

            len(scripts)
            >
            len(forms),


        "backend_hidden":

            js_network
            and spa_detected,


        "simple_site":

            len(scripts) < 3
            and not spa_detected,


        "complex_frontend":

            len(scripts) > 10
            or event_attrs > 30

    }



    # =====================================================
    # RETORNO COMPATIBLE
    # =====================================================

    return {

        # originales

        "scripts":
            len(scripts),

        "hidden_inputs":
            len(hidden),

        "data_actions":
            len(actions),

        "js_network":
            js_network,


        # profundidad añadida

        "inline_js_blocks":
            len(inline_js),

        "external_scripts":
            len(external_scripts),

        "hidden_sensitive":
            hidden_sensitive,

        "event_handlers":
            event_attrs,

        "framework_hints":
            framework_hints,

        "signals":
            signals,


        # nueva lectura SOC

        "forms":
            len(forms),


        "external_domains":
            external_domains,


        "dom_complexity":
            dom_complexity,


        "architecture":

            architecture,


        "meta":

            {
                "analysis":
                    "passive_dom_semantics",

                "execution":
                    False,

                "correlation_ready":
                    True

            }

    }

# ------------------------ TIMING DIFERENCIAL (ADVANCED) ---------------------------
def timing_diff(session, url):
    """
    Análisis temporal diferencial GET / HEAD / OPTIONS.

    Lectura forense de comportamiento HTTP.

    Filosofía:
    - activo controlado
    - no intrusivo
    - orientado a señales
    - sin explotación

    Observa:
    - diferencias entre métodos
    - estabilidad temporal
    - posibles capas intermedias
    - coherencia del backend
    """

    def measure(method):

        timings = []

        errors = 0


        for _ in range(TIMING_SAMPLES):

            try:

                t0 = time.time()

                response = session.request(
                    method,
                    url,
                    timeout=TIMEOUT
                )

                dt = time.time() - t0


                # =========================
                # FILTRO SUAVE DE RUIDO
                # =========================

                if (
                    0 < dt < TIMEOUT
                ):
                    timings.append(dt)


            except Exception:

                errors += 1

                continue


        return timings, errors



    # =====================================================
    # WARM-UP
    # =====================================================

    try:

        session.get(
            url,
            timeout=TIMEOUT
        )

    except Exception:

        pass



    # =====================================================
    # MEDICIÓN MULTIMÉTODO
    # =====================================================

    g, g_errors = measure(
        "GET"
    )

    h, h_errors = measure(
        "HEAD"
    )

    o, o_errors = measure(
        "OPTIONS"
    )



    # =====================================================
    # FALLBACK SEGURO
    # =====================================================

    if not g or not o:

        return {

            "get_avg": None,

            "head_avg": None,

            "opt_avg": None,

            "jitter": None,

            "jitter_high": False,

            "method_gap": False,

            "signals": [
                "insufficient_samples"
            ]

        }



    # =====================================================
    # MÉTRICAS BASE
    # =====================================================

    get_avg = statistics.mean(
        g
    )

    opt_avg = statistics.mean(
        o
    )

    head_avg = (
        statistics.mean(h)
        if h
        else 0
    )


    jitter = (

        statistics.pstdev(g)

        if len(g) > 1

        else 0

    )


    gap = abs(
        get_avg -
        opt_avg
    )



    # =====================================================
    # DISPERSIÓN TEMPORAL
    # =====================================================

    get_range = (

        max(g) -
        min(g)

        if g

        else 0

    )


    method_latency = {

        "GET_vs_HEAD":

            abs(
                get_avg -
                head_avg
            )
            if head_avg
            else None,


        "GET_vs_OPTIONS":

            gap

    }



    # =====================================================
    # LECTURA SEMÁNTICA
    # =====================================================

    signals = []


    if jitter > JITTER_THRESHOLD:

        signals.append(
            "timing_instability"
        )


    if gap > 0.6:

        signals.append(
            "method_processing_gap"
        )


    if (
        head_avg
        and
        head_avg < get_avg * 0.5
    ):

        signals.append(
            "head_optimized"
        )


    if opt_avg > get_avg * 1.3:

        signals.append(
            "options_heavy_logic"
        )


    if (
        jitter < 0.15
        and
        gap < 0.2
    ):

        signals.append(
            "uniform_backend_path"
        )



    # =====================================================
    # NUEVAS SEÑALES SOC
    # =====================================================

    behavior = {

        "stable_response":

            jitter < JITTER_THRESHOLD,


        "high_variance":

            get_range > 1.0,


        "method_divergence":

            gap > 0.6,


        "possible_cache_layer":

            (
                head_avg
                and
                head_avg < get_avg * 0.5
            ),


        "backend_consistent":

            (
                jitter < 0.15
                and
                gap < 0.2
            )

    }



    # =====================================================
    # PERFIL TEMPORAL
    # =====================================================

    if (
        jitter < 0.15
        and gap < 0.2
    ):

        profile = "predictable"


    elif jitter > JITTER_THRESHOLD:

        profile = "dynamic"


    else:

        profile = "mixed"



    # =====================================================
    # RETORNO COMPATIBLE
    # =====================================================

    return {


        # originales

        "get_avg":
            round(get_avg, 3),


        "head_avg":
            round(head_avg, 3),


        "opt_avg":
            round(opt_avg, 3),


        "jitter":
            round(jitter, 3),


        "jitter_high":
            jitter > JITTER_THRESHOLD,


        "method_gap":
            gap > 0.6,



        "samples":

            {

                "get":
                    len(g),


                "head":
                    len(h),


                "options":
                    len(o)

            },


        "signals":
            signals,



        # nuevas capas

        "statistics":

            {

                "get_range":
                    round(get_range, 3),


                "method_latency":

                    method_latency

            },


        "errors":

            {

                "get":
                    g_errors,


                "head":
                    h_errors,


                "options":
                    o_errors

            },


        "behavior":

            behavior,


        "profile":

            profile,


        "meta":

            {

                "analysis":
                    "http_timing_behavior",


                "correlation_ready":
                    True,


                "execution":
                    "controlled"

            }

    }
# ------------------------ SUPERFICIE BACKEND---------------------
def backend_surface(session, url):
    """
    Análisis avanzado de superficie backend.

    Filosofía:
    - activo controlado
    - pasivo contextual
    - sin modificación de estado

    Observa:
    - métodos declarados
    - comportamiento real
    - capas intermedias
    - coherencia backend
    - exposición operativa
    """

    signals = []
    methods = []
    unusual = []

    observations = {}
    stimuli = []


    # =====================================================
    # OPTIONS PRIMARIO
    # =====================================================

    try:

        opt = session.options(
            url,
            timeout=TIMEOUT
        )

        allow = (
            opt.headers.get("Allow", "")
            or
            opt.headers.get("allow", "")
        )

        observations["options_status"] = (
            opt.status_code
        )

        observations["allow_header"] = (
            allow
        )


    except Exception:

        return {

            "methods": [],
            "unusual": [],

            "risk_profile":
                "unknown",

            "signals":
                [
                    "options_unavailable"
                ]

        }



    # =====================================================
    # NORMALIZACIÓN
    # =====================================================

    methods = sorted({

        m.strip().upper()

        for m in allow.split(",")

        if m.strip()

    })


    safe_methods = {

        "GET",
        "HEAD",
        "OPTIONS"

    }


    common_methods = {

        "POST",
        "PUT",
        "DELETE",
        "PATCH"

    }


    exotic_methods = {

        "TRACE",
        "CONNECT",
        "DEBUG",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK"

    }


    unusual = [

        m

        for m in methods

        if m not in (
            safe_methods
            |
            common_methods
        )

    ]



    # =====================================================
    # LECTURA DE MÉTODOS EXPUESTOS
    # =====================================================

    if "TRACE" in methods:

        signals.append(
            "trace_enabled"
        )


    if (
        common_methods
        &
        set(methods)
    ):

        signals.append(
            "state_changing_methods"
        )


    if any(
        m in exotic_methods
        for m in methods
    ):

        signals.append(
            "exotic_methods_exposed"
        )


    if not methods:

        signals.append(
            "allow_header_empty"
        )


    if "OPTIONS" not in methods:

        signals.append(
            "options_not_advertised"
        )



    # =====================================================
    # ESTÍMULO HEAD VS GET
    # =====================================================

    r_get = None

    try:

        stimuli.append(
            "HEAD_GET_COMPARISON"
        )

        r_head = session.head(
            url,
            timeout=TIMEOUT
        )


        r_get = session.get(
            url,
            timeout=TIMEOUT
        )


        observations["head_status"] = (
            r_head.status_code
        )

        observations["get_status"] = (
            r_get.status_code
        )


        if (
            r_head.status_code
            !=
            r_get.status_code
        ):

            signals.append(
                "method_status_divergence"
            )


    except Exception:

        pass



    # =====================================================
    # ESTÍMULO METHOD OVERRIDE
    # =====================================================

    try:

        stimuli.append(
            "METHOD_OVERRIDE_CHECK"
        )


        r_override = session.post(

            url,

            headers={

                "X-HTTP-Method-Override":
                    "DELETE"

            },

            timeout=TIMEOUT

        )


        observations["override_status"] = (
            r_override.status_code
        )


        if r_override.status_code not in (
            400,
            405
        ):

            signals.append(
                "method_override_accepted"
            )


    except Exception:

        pass



    # =====================================================
    # DETECCIÓN CAPAS INTERMEDIAS
    # =====================================================

    proxy_headers = (

        "Via",
        "X-Forwarded-For",
        "X-Proxy",
        "X-Gateway",
        "X-Cache",
        "CF-Ray",
        "Server-Timing"

    )


    try:

        if r_get:

            detected = [

                h

                for h in proxy_headers

                if h in r_get.headers

            ]


            if detected:

                signals.append(
                    "gateway_or_proxy_detected"
                )


                observations[
                    "proxy_headers"
                ] = detected


    except Exception:

        pass



    # =====================================================
    # DECLARACIÓN VS REALIDAD
    # =====================================================

    try:

        if (

            "GET" not in methods

            and

            r_get

            and

            r_get.status_code < 400

        ):

            signals.append(
                "allow_mismatch_real_behavior"
            )


    except Exception:

        pass



    # =====================================================
    # PERFIL SEMÁNTICO
    # =====================================================

    if (

        any(
            m in exotic_methods
            for m in methods
        )

        or

        "method_override_accepted"
        in signals

    ):

        risk_profile = (
            "elevated"
        )


    elif (

        common_methods
        &
        set(methods)

    ):

        risk_profile = (
            "moderate"
        )


    elif methods:

        risk_profile = (
            "low"
        )


    else:

        risk_profile = (
            "unknown"
        )



    # =====================================================
    # LECTURA INVERSA BACKEND
    # =====================================================

    backend_profile = {

        "method_surface":

            len(methods),


        "declared_complexity":

            (
                "high"
                if len(methods) > 6
                else
                "normal"
            ),


        "stateful_behavior":

            bool(
                common_methods
                &
                set(methods)
            ),


        "intermediate_layer_hint":

            (
                "possible"
                if
                "gateway_or_proxy_detected"
                in signals

                else
                "unknown"
            )

    }



    # =====================================================
    # RETORNO COMPATIBLE
    # =====================================================

    return {


        # originales

        "methods":
            methods,


        "unusual":
            unusual,


        "risk_profile":
            risk_profile,


        "signals":
            signals,



        # enriquecimiento SOC

        "observations":
            observations,


        "stimuli":
            stimuli,


        "backend_profile":
            backend_profile,


        "meta":

            {

                "analysis":
                    "backend_behavior_surface",


                "state_change":
                    False,


                "correlation_ready":
                    True

            }

    }



# ------------------------ SCORING (ADVANCED) ----------------------------
def score(sig):
    """
    Scoring heurístico multidimensional.

    No mide vulnerabilidades.
    Mide concentración de señales:
    - comportamiento HTTP
    - dinámica temporal
    - arquitectura frontend
    - superficie backend
    - coherencia entre capas

    Filosofía:
    Una señal aislada es ruido.
    Varias capas alineadas forman evidencia.
    """

    score = 0
    correlations = 0

    http = sig.get("http", {})
    timing = sig.get("timing", {})
    dom = sig.get("dom", {})
    surface = sig.get("surface", {})


    # =====================================================
    # HTTP SEMANTICS
    # =====================================================

    if http.get("hash_change"):
        score += 3

    if http.get("etag"):
        score += 1


    cache = http.get("cache_signals", {})

    if cache.get("cache_ambiguous"):
        score += 1


    if http.get("semantic_mismatch"):
        score += 2



    # =====================================================
    # TIMING BEHAVIOR
    # =====================================================

    if timing.get("jitter_high"):
        score += 2

    if timing.get("method_gap"):
        score += 2


    timing_signals = timing.get("signals", [])

    if "method_processing_gap" in timing_signals:
        score += 2


    if "options_heavy_logic" in timing_signals:
        score += 1


    if "uniform_backend_path" in timing_signals:
        score += 1



    # =====================================================
    # DOM / FRONTEND INTELLIGENCE
    # =====================================================

    hidden = dom.get("hidden_inputs", 0)

    if hidden:
        score += 2


    if dom.get("hidden_sensitive"):
        score += 3


    if dom.get("js_network"):
        score += 2


    dom_signals = dom.get("signals", [])


    if "spa_frontend" in dom_signals:
        score += 1


    if "logic_externalized" in dom_signals:
        score += 1



    # =====================================================
    # BACKEND SURFACE
    # =====================================================

    unusual = surface.get("unusual", [])

    if unusual:
        score += 3


    risk = surface.get("risk_profile")


    if risk == "elevated":
        score += 2

    elif risk == "moderate":
        score += 1



    surface_signals = surface.get("signals", [])


    if "method_override_accepted" in surface_signals:
        score += 3


    if "gateway_or_proxy_detected" in surface_signals:
        score += 1



    # =====================================================
    # CORRELACIÓN MULTICAPA
    # =====================================================

    #
    # No buscamos indicadores.
    # Buscamos comportamiento coherente.
    #


    if (
        http.get("hash_change")
        and dom.get("js_network")
        and timing.get("method_gap")
    ):
        score += 3
        correlations += 1



    if (
        dom.get("hidden_sensitive")
        and surface.get("methods")
        and timing.get("method_gap")
    ):
        score += 3
        correlations += 1



    if (
        http.get("semantic_mismatch")
        and dom.get("js_network")
    ):
        score += 2
        correlations += 1



    # =====================================================
    # CONTEXTO SOC
    # =====================================================

    if correlations >= 3:
        score += 3

    elif correlations == 2:
        score += 2

    elif correlations == 1:
        score += 1



    # =====================================================
    # NORMALIZACIÓN
    # =====================================================

    if score < 0:
        score = 0


    return score

# ------------------------ INTERPRETACIÓN (ADVANCED) ----------------------
def insights(sig):
    """
    Interpretación cognitiva multidimensional.

    Traduce señales técnicas:
        evento -> contexto -> significado operacional

    No confirma vulnerabilidades.
    Explica comportamientos observables.

    Diseñado para:
    - SOC analysis
    - threat modeling
    - arquitectura inversa
    - lectura de superficie
    """

    out = []

    http = sig.get("http", {})
    timing = sig.get("timing", {})
    dom = sig.get("dom", {})
    surface = sig.get("surface", {})


    # =====================================================
    # HTTP BEHAVIOR
    # =====================================================

    if http.get("hash_change"):
        out.append(
            "Respuesta variable detectada → existe comportamiento dinámico "
            "(estado interno, personalización, experimentación o generación bajo demanda)."
        )


    if http.get("etag"):
        out.append(
            "ETag presente → el sistema mantiene mecanismos de validación "
            "de representación o cache consciente del recurso."
        )


    cache = http.get("cache_signals", {})

    if cache.get("cache_ambiguous"):
        out.append(
            "Política de cache poco evidente → posible lógica intermedia "
            "entre cliente, proxy y aplicación."
        )


    if http.get("semantic_mismatch"):
        out.append(
            "Respuesta declarada y contenido no coinciden → revisar "
            "coherencia entre capa HTTP y aplicación."
        )



    # =====================================================
    # TEMPORAL INTELLIGENCE
    # =====================================================

    if timing.get("method_gap"):
        out.append(
            "Métodos HTTP presentan comportamiento temporal diferente → "
            "posibles rutas internas diferenciadas, middleware o controles condicionales."
        )


    if "method_processing_gap" in timing.get("signals", []):

        out.append(
            "GET y OPTIONS parecen recorrer caminos distintos → "
            "existe separación lógica entre capas de procesamiento."
        )


    if "options_heavy_logic" in timing.get("signals", []):

        out.append(
            "OPTIONS muestra procesamiento elevado → "
            "posible gateway, framework routing o capa intermedia activa."
        )


    if timing.get("jitter_high"):

        out.append(
            "Variación temporal elevada → comportamiento compatible con "
            "balanceo, servicios distribuidos, colas o infraestructura dinámica."
        )



    # =====================================================
    # FRONTEND / DOM INTELLIGENCE
    # =====================================================

    if dom.get("hidden_sensitive"):

        out.append(
            "Elementos ocultos con información sensible aparente → "
            "la aplicación mantiene estado interno o flujos multi-etapa."
        )


    if dom.get("js_network"):

        out.append(
            "JavaScript genera comunicación activa → "
            "la superficie funcional puede extenderse más allá del HTML visible."
        )


    dom_signals = dom.get("signals", [])


    if "spa_frontend" in dom_signals:

        out.append(
            "Frontend SPA detectado → "
            "la lógica principal probablemente reside en APIs y servicios auxiliares."
        )


    if "logic_externalized" in dom_signals:

        out.append(
            "Lógica externalizada → arquitectura separada entre presentación y recursos externos."
        )



    # =====================================================
    # BACKEND SURFACE
    # =====================================================

    if surface.get("unusual"):

        out.append(
            "Métodos HTTP fuera del patrón común observados → "
            "la interfaz expuesta merece revisión arquitectónica."
        )


    risk = surface.get("risk_profile")


    if risk == "elevated":

        out.append(
            "Superficie backend con señales elevadas → "
            "requiere correlación manual antes de sacar conclusiones."
        )


    elif risk == "moderate":

        out.append(
            "Superficie backend moderada → "
            "existen componentes adicionales visibles desde fuera."
        )



    # =====================================================
    # CORRELACIONES PROFUNDAS
    # =====================================================


    if (
        http.get("hash_change")
        and dom.get("js_network")
        and timing.get("method_gap")
    ):

        out.append(
            "Frontend dinámico + respuestas variables + diferencias temporales → "
            "posible arquitectura con lógica condicional no visible."
        )


    if (
        dom.get("hidden_sensitive")
        and surface.get("methods")
        and timing.get("method_gap")
    ):

        out.append(
            "Estado interno + métodos expuestos + rutas diferenciadas → "
            "modelo de aplicación con múltiples capas de decisión."
        )


    if (
        http.get("etag")
        and dom.get("js_network")
    ):

        out.append(
            "Cache inteligente junto a frontend activo → "
            "posible optimización para usuarios dinámicos o contenido personalizado."
        )



    # =====================================================
    # LECTURA FINAL
    # =====================================================

    if len(out) >= 6:

        out.append(
            "Múltiples capas presentan actividad coherente → "
            "la superficie observable representa una arquitectura compleja."
        )


    if not out:

        out.append(
            "Superficie homogénea → comportamiento consistente, "
            "sin señales fuertes de complejidad externa."
        )


    return out


# ------------------------ ORQUESTADOR ---------------------------------
def scan(url):
    """
    Orquestador principal de observación web.

    Ejecuta una lectura multicapa:

        HTTP
          ↓
        DOM
          ↓
        Timing
          ↓
        Backend Surface
          ↓
        Correlación cognitiva

    No explota.
    No modifica estado.
    Solo observa comportamiento externo.

    Diseñado para análisis SOC,
    threat modeling y arquitectura inversa.
    """

    session = build_session()

    phases = {}
    warnings = []
    execution = {}

    start_scan = time.time()


    # =====================================================
    # HTTP SEMANTICS
    # =====================================================

    t0 = time.time()

    try:

        http, resp = http_semantics(
            session,
            url
        )

        execution["http"] = "completed"

    except Exception as e:

        http, resp = {}, None

        warnings.append(
            f"http_semantics_error: {type(e).__name__}"
        )

        execution["http"] = "failed"


    phases["http"] = round(
        time.time() - t0,
        3
    )



    # =====================================================
    # DOM DEEP ANALYSIS
    # =====================================================

    t0 = time.time()

    try:

        dom = dom_deep(
            resp.text if resp else ""
        )

        execution["dom"] = "completed"


    except Exception as e:

        dom = {}

        warnings.append(
            f"dom_error: {type(e).__name__}"
        )

        execution["dom"] = "failed"


    phases["dom"] = round(
        time.time() - t0,
        3
    )



    # =====================================================
    # TEMPORAL DIFFERENCE
    # =====================================================

    t0 = time.time()

    try:

        timing = timing_diff(
            session,
            url
        )

        execution["timing"] = "completed"


    except Exception as e:

        timing = {}

        warnings.append(
            f"timing_error: {type(e).__name__}"
        )

        execution["timing"] = "failed"


    phases["timing"] = round(
        time.time() - t0,
        3
    )



    # =====================================================
    # BACKEND SURFACE
    # =====================================================

    t0 = time.time()

    try:

        surface = backend_surface(
            session,
            url
        )

        execution["surface"] = "completed"


    except Exception as e:

        surface = {}

        warnings.append(
            f"surface_error: {type(e).__name__}"
        )

        execution["surface"] = "failed"


    phases["surface"] = round(
        time.time() - t0,
        3
    )



    # =====================================================
    # SIGNAL PACKAGE
    # =====================================================

    sig = {

        "http": http,

        "dom": dom,

        "timing": timing,

        "surface": surface
    }



    # =====================================================
    # COGNITIVE LAYER
    # =====================================================

    try:

        priority = score(sig)

    except Exception as e:

        priority = 0

        warnings.append(
            f"score_error: {type(e).__name__}"
        )


    try:

        generated_insights = insights(sig)

    except Exception as e:

        generated_insights = []

        warnings.append(
            f"insights_error: {type(e).__name__}"
        )



    # =====================================================
    # FINAL OBSERVATION
    # =====================================================

    return {

        "url": url,


        "signals": sig,


        "priority": priority,


        "insights": generated_insights,


        "meta": {

            "phases_sec": phases,


            "warnings": warnings,


            "execution": execution,


            "runtime_sec": round(
                time.time() - start_scan,
                3
            ),


            "analysis": {

                "layers": [
                    "http",
                    "dom",
                    "timing",
                    "backend"
                ],

                "mode":
                    "passive_behavioral_observation",

                "correlation_ready":
                    True
            }
        }
    }


# ------------------------ VISUAL NEON ---------------------------------
def render(report):
    """
    Render multidimensional SOC.

    No transforma datos.
    No elimina señales.
    Solo organiza la observación
    para lectura humana.

    Diseñado para:
    - OSINT
    - SOC
    - análisis forense
    - correlación multicapa
    """

    console.print(
        Panel(
            Text(
                "OsintSignalsF — NEON SURGICAL MULTI-DIMENSIONAL MODE",
                style="bold neon_magenta"
            ),
            border_style="bright_cyan"
        )
    )


    # =====================================================
    # HELPERS
    # =====================================================

    def flatten(data, prefix=""):

        lines = []

        if isinstance(data, dict):

            for k, v in data.items():

                key = (
                    f"{prefix}.{k}"
                    if prefix
                    else str(k)
                )

                lines.extend(
                    flatten(v, key)
                )


        elif isinstance(data, list):

            for i, item in enumerate(data):

                key = f"{prefix}[{i}]"

                lines.extend(
                    flatten(item, key)
                )


        else:

            lines.append(
                (
                    prefix,
                    data
                )
            )


        return lines



    # =====================================================
    # SIGNAL TABLE
    # =====================================================

    table = Table(
        title="🧬 MATRIZ MULTICAPA DE SEÑALES",
        header_style="bold bright_yellow",
        show_lines=True
    )


    table.add_column(
        "Capa",
        style="bold bright_blue"
    )

    table.add_column(
        "Señal",
        style="bright_green"
    )

    table.add_column(
        "Valor",
        style="white"
    )



    colors = {

        "http":
            "bright_cyan",

        "dom":
            "bright_magenta",

        "timing":
            "bright_yellow",

        "surface":
            "bright_red"
    }



    signals = report.get(
        "signals",
        {}
    )


    for layer, data in signals.items():

        color = colors.get(
            layer,
            "white"
        )


        flattened = flatten(
            data
        )


        if not flattened:

            table.add_row(
                Text(layer, style=color),
                "-",
                "sin datos"
            )

            continue



        first = True


        for key, value in flattened:


            table.add_row(

                Text(
                    layer if first else "",
                    style=color
                ),

                Text(
                    str(key),
                    style=color
                ),

                str(value)

            )


            first = False



    console.print(table)



    # =====================================================
    # COGNITIVE LAYER
    # =====================================================

    insights = report.get(
        "insights",
        []
    )


    if insights:

        console.print(

            Panel(

                "\n".join(
                    f"🧠 {i}"
                    for i in insights
                ),

                title="Interpretación Cognitiva",

                border_style="bright_magenta"
            )
        )



    # =====================================================
    # PRIORITY ENGINE
    # =====================================================

    priority = report.get(
        "priority",
        0
    )


    if priority >= 10:

        style = "bright_red"

    elif priority >= 6:

        style = "bright_yellow"

    else:

        style = "bright_green"



    console.print(

        Panel(

            Text(
                f"PRIORITY SCORE: {priority}",
                style=f"bold {style}"
            ),

            title="🔥 Evaluación",

            border_style=style
        )
    )



    # =====================================================
    # TELEMETRY
    # =====================================================

    meta = report.get(
        "meta",
        {}
    )


    if meta:


        meta_table = Table(
            title="⚙️ Telemetría del Observador",
            show_lines=True
        )


        meta_table.add_column(
            "Elemento"
        )


        meta_table.add_column(
            "Valor"
        )


        for key, value in meta.items():


            if isinstance(value, (dict,list)):

                value = "\n".join(
                    f"- {x}: {y}"
                    for x,y in flatten(value)
                )


            meta_table.add_row(
                str(key),
                str(value)
            )


        console.print(
            meta_table
        )



    # =====================================================
    # RESUMEN OPERACIONAL
    # =====================================================

    total_signals = len(
        flatten(signals)
    )


    console.print(

        Panel(

            Text(

                f"""
🔍 Señales extraídas: {total_signals}
🧬 Capas analizadas: {len(signals)}
⚙️ Estado: {'Completo' if not report.get('meta',{}).get('warnings') else 'Parcial'}
🧠 Motor: Correlación multidimensional
""",

                style="bold bright_cyan"
            ),

            title="Estado del Observador",

            border_style="bright_blue"

        )
    )

# ----------------------------- CLI (NEON ALCHEMICAL MODE) -----------------------------
def graceful_exit(signum, frame):
    console.print("\n🛑 Interrupción detectada. Cerrando de forma segura…",
                  style="bold bright_red")
    sys.exit(130)

signal.signal(signal.SIGINT, graceful_exit)

def neon_banner():
    """
    Banner de identidad del motor.

    No es decoración.
    Representa estado:
    observación activa,
    inteligencia silenciosa
    y análisis multicapa.
    """

    console.print()

    # =====================================================
    # CAPA PRINCIPAL
    # =====================================================

    title = Text(
        justify="center"
    )

    title.append(
        "O S I N T S I G N A L S F\n",
        style="bold bright_magenta"
    )

    title.append(
        "◢ NEON ALCHEMICAL INTELLIGENCE ENGINE ◣",
        style="bold bright_cyan"
    )


    # =====================================================
    # SUBTÍTULO
    # =====================================================

    subtitle = Text(
        justify="center"
    )


    subtitle.append(
        "\n\n"
        "SURGICAL OBSERVATION  •  MULTI-LAYER SIGNAL FUSION\n",
        style="bright_blue"
    )


    subtitle.append(
        "Passive Intelligence  •  Behavioral Analysis  •  Reality Mapping\n",
        style="dim bright_cyan"
    )


    subtitle.append(
        "\n"
        "ByMakaveli — New Era Protocol",
        style="bold bright_magenta"
    )



    # =====================================================
    # ESTADO DEL MOTOR
    # =====================================================

    status = Text(
        justify="center"
    )


    status.append(
        "\n\n"
        "◆ ENGINE STATUS: ",
        style="dim white"
    )


    status.append(
        "ONLINE",
        style="bold bright_green"
    )


    status.append(
        "   ◆ MODE: ",
        style="dim white"
    )


    status.append(
        "OBSERVATION",
        style="bold bright_yellow"
    )


    status.append(
        "\n"
        "◆ SIGNAL FUSION: ACTIVE",
        style="bold bright_cyan"
    )



    # =====================================================
    # ENSAMBLE VISUAL
    # =====================================================

    body = Align.center(
        title +
        subtitle +
        status
    )


    console.print(

        Panel(

            body,

            border_style="bright_magenta",

            padding=(1,8),

            title="⧉ REALITY OBSERVER CORE ⧉",

            title_align="center"

        )

    )


    # =====================================================
    # FIRMA INFERIOR
    # =====================================================

    footer = Text(
        "\n     observe quietly • correlate deeply • decide precisely\n",
        style="italic dim bright_cyan",
        justify="center"
    )


    console.print(
        footer
    )

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
