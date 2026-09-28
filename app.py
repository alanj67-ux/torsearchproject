import os
import re
import hmac
import ipaddress
from urllib.parse import (
    quote,
    quote_plus,
    urljoin,
    urlsplit,
    urlunsplit,
    urlencode,
    parse_qsl,
)

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, Response
from markupsafe import escape


app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================

TOR_PROXY = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

DEFAULT_ENGINE = "duckduckgo.com"

ENDPOINTS = {
    "google.com": "https://www.google.com/search?q={}&num=20",
    "duckduckgo.com": "https://html.duckduckgo.com/html/?q={}",
    "bing.com": "https://www.bing.com/search?q={}",
    "startpage.com": "https://www.startpage.com/sp/search?query={}",
    "search.brave.com": "https://search.brave.com/search?q={}",
    "youtube.com": "https://www.youtube.com/results?search_query={}",
}

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

MAX_RESPONSE_SIZE = 15 * 1024 * 1024
MAX_REDIRECTS = 6


# ============================================================
# LOGIN
# ============================================================

SITE_USERNAME = os.environ.get("SITE_USERNAME", "alan")
SITE_PASSWORD = os.environ.get("SITE_PASSWORD")


@app.before_request
def authenticate():
    if request.path == "/health":
        return None

    if not SITE_PASSWORD:
        return Response(
            "SITE_PASSWORD environment variable has not been set.",
            status=500,
            mimetype="text/plain",
        )

    auth = request.authorization

    if auth is None:
        return login_required()

    username_ok = hmac.compare_digest(
        auth.username or "",
        SITE_USERNAME,
    )

    password_ok = hmac.compare_digest(
        auth.password or "",
        SITE_PASSWORD,
    )

    if not username_ok or not password_ok:
        return login_required()

    return None


def login_required():
    return Response(
        "Login required",
        status=401,
        headers={
            "WWW-Authenticate": 'Basic realm="Tor Search"'
        },
        mimetype="text/plain",
    )


# ============================================================
# HOME PAGE
# ============================================================

INDEX = """
<!doctype html>

<html>
<head>
<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
>

<title>Tor Search</title>

<style>

body {
    background: #0d1117;
    color: #e6edf3;
    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        Monaco,
        Consolas,
        monospace;

    display: flex;
    flex-direction: column;
    align-items: center;

    padding: 14vh 20px 40px 20px;
}

h1 {
    font-weight: 400;
    letter-spacing: .05em;
    color: #7ee787;
    margin-bottom: 30px;
}

form {
    display: flex;
    gap: .5rem;
    width: 100%;
    max-width: 700px;
}

input {
    background: #161b22;
    border: 1px solid #30363d;
    color: #e6edf3;

    padding: .75rem 1rem;
    font-size: 1rem;
    border-radius: 6px;

    font-family: inherit;
    flex: 1;
}

button {
    background: #238636;
    color: #fff;

    border: 0;
    padding: .75rem 1.3rem;

    font-size: 1rem;
    border-radius: 6px;

    cursor: pointer;
    font-family: inherit;
}

button:hover {
    background: #2ea043;
}

.hint {
    color: #8b949e;

    font-size: .85rem;
    margin-top: 2rem;

    max-width: 700px;
    text-align: center;
    line-height: 1.6;
}

.status {
    margin-top: 25px;

    color: #7ee787;
    font-size: .8rem;
}

</style>
</head>

<body>

<h1>tor search</h1>

<form action="/search" method="get">

<input
    name="q"
    placeholder="search · or youtube.com cats"
    autocomplete="off"
    autofocus
>

<button type="submit">
search
</button>

</form>

<p class="hint">

Use normal text to search DuckDuckGo.

<br><br>

You can also begin with:

<br>

google.com ·
duckduckgo.com ·
bing.com ·
startpage.com ·
search.brave.com ·
youtube.com

</p>

<div class="status">
requests routed through Tor
</div>

</body>
</html>
"""


@app.route("/")
def index():
    return Response(
        INDEX,
        mimetype="text/html",
    )


@app.route("/health")
def health():
    return Response(
        "OK",
        mimetype="text/plain",
    )


# ============================================================
# SECURITY
# ============================================================

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "host.docker.internal",
}


def safe_target(url):
    try:
        parsed = urlsplit(url)
    except Exception:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    if not parsed.hostname:
        return False

    hostname = parsed.hostname.lower().rstrip(".")

    if hostname in BLOCKED_HOSTS:
        return False

    if hostname.endswith(".local"):
        return False

    if hostname.endswith(".internal"):
        return False

    try:
        ip = ipaddress.ip_address(hostname)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    except ValueError:
        pass

    return True


# ============================================================
# TOR FETCH
# ============================================================

def fetch(url, method="GET", data=None):
    current_url = url

    for _ in range(MAX_REDIRECTS + 1):

        if not safe_target(current_url):
            raise requests.RequestException(
                "blocked destination"
            )

        r = requests.request(
            method,
            current_url,

            data=data,

            proxies=TOR_PROXY,

            headers={
                "User-Agent": UA,
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "*/*",
            },

            timeout=(10, 40),
            allow_redirects=False,
            stream=True,
        )

        if r.status_code in (
            301,
            302,
            303,
            307,
            308,
        ):
            location = r.headers.get("Location")

            if not location:
                break

            next_url = urljoin(
                current_url,
                location,
            )

            status_code = r.status_code
            r.close()

            current_url = next_url

            if status_code in (
                301,
                302,
                303,
            ):
                method = "GET"
                data = None

            continue

        length = r.headers.get(
            "Content-Length"
        )

        if length:
            try:
                if int(length) > MAX_RESPONSE_SIZE:
                    r.close()

                    raise requests.RequestException(
                        "response too large"
                    )

            except ValueError:
                pass

        content = bytearray()

        for chunk in r.iter_content(
            chunk_size=65536
        ):
            if not chunk:
                continue

            content.extend(chunk)

            if len(content) > MAX_RESPONSE_SIZE:
                r.close()

                raise requests.RequestException(
                    "response too large"
                )

        r._content = bytes(content)
        r.close()

        return r

    raise requests.RequestException(
        "too many redirects"
    )


# ============================================================
# PROXY URL
# ============================================================

def proxy_url(target):
    if not target:
        return "#"

    target = target.strip()

    if target.startswith("#"):
        return target

    parsed = urlsplit(target)

    if parsed.scheme not in (
        "http",
        "https",
    ):
        return "#"

    fragment = parsed.fragment

    clean_target = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.query,
            "",
        )
    )

    result = (
        "/proxy?url="
        + quote(
            clean_target,
            safe="",
        )
    )

    if fragment:
        result += "#" + quote(
            fragment,
            safe="",
        )

    return result


# ============================================================
# CSS REWRITE
# ============================================================

CSS_URL_RE = re.compile(
    r"url\(\s*(['\"]?)(.*?)\1\s*\)",
    re.IGNORECASE,
)


def rewrite_css(css, base_url):

    def replace(match):
        target = match.group(2).strip()

        if not target:
            return match.group(0)

        if target.startswith(
            (
                "data:",
                "#",
                "blob:",
            )
        ):
            return match.group(0)

        absolute = urljoin(
            base_url,
            target,
        )

        proxied = proxy_url(
            absolute
        )

        return f"url('{proxied}')"

    return CSS_URL_RE.sub(
        replace,
        css,
    )


# ============================================================
# HTML REWRITE
# ============================================================

def rewrite_html(html, base_url):

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    for tag in soup.find_all("base"):
        tag.decompose()

    # Remove JavaScript so pages cannot make direct browser-side
    # network requests outside the proxy.
    for script in soup.find_all("script"):
        script.decompose()

    for obj in soup.find_all(
        [
            "object",
            "embed",
        ]
    ):
        obj.decompose()

    for meta in soup.find_all("meta"):
        value = meta.get(
            "http-equiv",
            "",
        ).lower()

        if value == "refresh":
            meta.decompose()

    for tag in soup.find_all(True):

        for attribute in list(
            tag.attrs.keys()
        ):
            if attribute.lower().startswith(
                "on"
            ):
                del tag.attrs[attribute]

        tag.attrs.pop(
            "integrity",
            None,
        )

        tag.attrs.pop(
            "crossorigin",
            None,
        )

        if "style" in tag.attrs:
            tag["style"] = rewrite_css(
                tag["style"],
                base_url,
            )

    for style in soup.find_all("style"):

        if style.string:
            style.string.replace_with(
                rewrite_css(
                    style.string,
                    base_url,
                )
            )

    resource_attributes = {
        "a": "href",
        "area": "href",
        "img": "src",
        "iframe": "src",
        "source": "src",
        "video": "src",
        "audio": "src",
        "track": "src",
        "link": "href",
    }

    for tag_name, attribute in resource_attributes.items():

        for tag in soup.find_all(
            tag_name
        ):

            value = tag.get(
                attribute
            )

            if not value:
                continue

            value = value.strip()

            if value.startswith(
                (
                    "#",
                    "data:",
                    "blob:",
                )
            ):
                continue

            absolute = urljoin(
                base_url,
                value,
            )

            tag[attribute] = proxy_url(
                absolute
            )

    for tag in soup.find_all(
        "video"
    ):
        poster = tag.get(
            "poster"
        )

        if poster:

            absolute = urljoin(
                base_url,
                poster,
            )

            tag["poster"] = proxy_url(
                absolute
            )

    for tag in soup.find_all(
        [
            "img",
            "source",
        ]
    ):
        tag.attrs.pop(
            "srcset",
            None,
        )

    for form in soup.find_all(
        "form"
    ):

        original_action = (
            form.get("action")
            or base_url
        )

        absolute_action = urljoin(
            base_url,
            original_action,
        )

        method = form.get(
            "method",
            "get",
        ).lower()

        if method not in (
            "get",
            "post",
        ):
            method = "get"

        form["action"] = "/form"
        form["method"] = method

        hidden = soup.new_tag(
            "input"
        )

        hidden["type"] = "hidden"
        hidden["name"] = "_target"
        hidden["value"] = absolute_action

        form.insert(
            0,
            hidden,
        )

    csp = soup.new_tag("meta")

    csp["http-equiv"] = (
        "Content-Security-Policy"
    )

    csp["content"] = (
        "default-src 'self' data: blob:; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data:; "
        "script-src 'none'; "
        "connect-src 'self'; "
        "frame-src 'self'; "
        "media-src 'self' data: blob:; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self';"
    )

    if soup.head:
        soup.head.insert(
            0,
            csp,
        )
    else:
        head = soup.new_tag(
            "head"
        )

        head.append(
            csp
        )

        if soup.html:
            soup.html.insert(
                0,
                head,
            )
        else:
            soup.insert(
                0,
                head,
            )

    return str(soup)


# ============================================================
# SEARCH
# ============================================================

def split_search(query):

    first, separator, rest = (
        query.partition(" ")
    )

    if separator and rest:

        candidate = (
            first.lower()
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
        )

        if candidate in ENDPOINTS:
            return (
                candidate,
                rest.strip(),
            )

    return (
        DEFAULT_ENGINE,
        query,
    )


@app.route("/search")
def search():

    q = request.args.get(
        "q",
        "",
    ).strip()

    if not q:
        return Response(
            "<pre>empty query</pre>",
            status=400,
            mimetype="text/html",
        )

    domain, query = split_search(q)

    template = ENDPOINTS[
        domain
    ]

    target = template.format(
        quote_plus(query)
    )

    try:
        r = fetch(
            target
        )

    except requests.RequestException as e:

        return Response(
            (
                "<pre>"
                "Tor fetch failed:\n\n"
                f"{escape(str(e))}\n\n"
                "Is Tor running on "
                "127.0.0.1:9050?"
                "</pre>"
            ),
            status=502,
            mimetype="text/html",
        )

    content_type = (
        r.headers.get(
            "Content-Type",
            ""
        )
    )

    if "html" not in content_type.lower():

        return Response(
            r.content,
            status=r.status_code,
            content_type=content_type,
        )

    text = r.content.decode(
        r.encoding or "utf-8",
        errors="replace",
    )

    rewritten = rewrite_html(
        text,
        r.url,
    )

    soup = BeautifulSoup(
        rewritten,
        "html.parser",
    )

    banner = BeautifulSoup(
        f"""
        <div style="
            background:#0d1117;
            color:#e6edf3;
            border-bottom:1px solid #30363d;
            padding:12px;
            font-family:monospace;
            position:relative;
            z-index:999999;
        ">

        <form
            action="/search"
            method="get"
            style="
                display:flex;
                gap:8px;
                margin:0 0 8px 0;
            "
        >

        <input
            name="q"
            value="{escape(q)}"
            autocomplete="off"
            style="
                flex:1;
                padding:8px;
            "
        >

        <button
            type="submit"
            style="
                padding:8px 14px;
            "
        >
        search
        </button>

        </form>

        <span
            style="
                color:#7ee787;
                font-size:12px;
            "
        >
        Tor → {escape(domain)}
        </span>

        &nbsp;

        <a
            href="/"
            style="
                color:#79c0ff;
                font-size:12px;
            "
        >
        home
        </a>

        </div>
        """,
        "html.parser",
    )

    if soup.body:
        soup.body.insert(
            0,
            banner,
        )

    return Response(
        str(soup),
        status=r.status_code,
        content_type="text/html; charset=utf-8",
    )


# ============================================================
# PAGE / RESOURCE PROXY
# ============================================================

@app.route("/proxy")
def proxy():

    target = request.args.get(
        "url",
        "",
    ).strip()

    if not safe_target(
        target
    ):
        return Response(
            "<pre>bad or blocked URL</pre>",
            status=400,
            mimetype="text/html",
        )

    try:
        r = fetch(
            target
        )

    except requests.RequestException as e:

        return Response(
            (
                "<pre>"
                "Proxy fetch failed:\n\n"
                f"{escape(str(e))}"
                "</pre>"
            ),
            status=502,
            mimetype="text/html",
        )

    content_type = (
        r.headers.get(
            "Content-Type",
            "application/octet-stream",
        )
    )

    lower_type = (
        content_type.lower()
    )

    if (
        "text/html" in lower_type
        or "application/xhtml+xml" in lower_type
    ):

        text = r.content.decode(
            r.encoding or "utf-8",
            errors="replace",
        )

        text = rewrite_html(
            text,
            r.url,
        )

        response = Response(
            text,
            status=r.status_code,
            content_type=(
                "text/html; charset=utf-8"
            ),
        )

    elif "text/css" in lower_type:

        text = r.content.decode(
            r.encoding or "utf-8",
            errors="replace",
        )

        text = rewrite_css(
            text,
            r.url,
        )

        response = Response(
            text,
            status=r.status_code,
            content_type=(
                "text/css; charset=utf-8"
            ),
        )

    else:

        response = Response(
            r.content,
            status=r.status_code,
            content_type=content_type,
        )

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    return response


# ============================================================
# PROXIED FORMS
# ============================================================

@app.route(
    "/form",
    methods=[
        "GET",
        "POST",
    ],
)
def proxy_form():

    target = (
        request.values.get(
            "_target",
            "",
        ).strip()
    )

    if not safe_target(
        target
    ):
        return Response(
            "<pre>bad or blocked form destination</pre>",
            status=400,
            mimetype="text/html",
        )

    if request.method == "GET":

        values = []

        for key in request.args:

            if key == "_target":
                continue

            for value in request.args.getlist(
                key
            ):
                values.append(
                    (
                        key,
                        value,
                    )
                )

        parsed = urlsplit(
            target
        )

        existing = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        new_query = urlencode(
            existing + values,
            doseq=True,
        )

        target = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                new_query,
                "",
            )
        )

        method = "GET"
        data = None

    else:

        method = "POST"
        data = []

        for key in request.form:

            if key == "_target":
                continue

            for value in request.form.getlist(
                key
            ):
                data.append(
                    (
                        key,
                        value,
                    )
                )

    try:
        r = fetch(
            target,
            method=method,
            data=data,
        )

    except requests.RequestException as e:

        return Response(
            (
                "<pre>"
                "Form request failed:\n\n"
                f"{escape(str(e))}"
                "</pre>"
            ),
            status=502,
            mimetype="text/html",
        )

    content_type = (
        r.headers.get(
            "Content-Type",
            "text/html",
        )
    )

    if "html" in content_type.lower():

        text = r.content.decode(
            r.encoding or "utf-8",
            errors="replace",
        )

        text = rewrite_html(
            text,
            r.url,
        )

        return Response(
            text,
            status=r.status_code,
            content_type=(
                "text/html; charset=utf-8"
            ),
        )

    return Response(
        r.content,
        status=r.status_code,
        content_type=content_type,
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            8888,
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
    )
