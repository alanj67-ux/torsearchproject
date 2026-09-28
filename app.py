import os
import re
import hmac
import secrets
import threading
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
from flask import Flask, request, Response, redirect


app = Flask(__name__)


# ============================================================
# LOGIN
# ============================================================

SITE_USERNAME = os.environ.get("SITE_USERNAME", "alan")
SITE_PASSWORD = os.environ.get("SITE_PASSWORD")


@app.before_request
def require_login():
    # Allow Render/Docker health checks.
    if request.path == "/health":
        return None

    if not SITE_PASSWORD:
        return Response(
            "SITE_PASSWORD has not been configured.",
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
            "WWW-Authenticate": 'Basic realm="Tor Browser Proxy"'
        },
        mimetype="text/plain",
    )


# ============================================================
# TOR
# ============================================================

TOR_PROXY = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}


# ============================================================
# SEARCH ENGINES
# ============================================================

# DuckDuckGo sometimes rejects Tor exit nodes.
# Use Brave as the default instead.
DEFAULT_ENGINE = "search.brave.com"

ENDPOINTS = {
    "google.com":
        "https://www.google.com/search?q={}&num=20",

    "duckduckgo.com":
        "https://html.duckduckgo.com/html/?q={}",

    "bing.com":
        "https://www.bing.com/search?q={}",

    "startpage.com":
        "https://www.startpage.com/sp/search?query={}",

    "search.brave.com":
        "https://search.brave.com/search?q={}",

    "youtube.com":
        "https://www.youtube.com/results?search_query={}",
}


# ============================================================
# SETTINGS
# ============================================================

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

MAX_REWRITE_SIZE = 25 * 1024 * 1024
MAX_REDIRECTS = 8


BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "host.docker.internal",
    "metadata.google.internal",
}


# ============================================================
# REMOTE COOKIE SESSIONS
# ============================================================

REMOTE_SESSIONS = {}
REMOTE_LOCK = threading.Lock()
MAX_REMOTE_SESSIONS = 100


def get_remote_session():
    sid = request.cookies.get("proxy_sid")
    created = False

    with REMOTE_LOCK:
        if not sid or sid not in REMOTE_SESSIONS:
            sid = secrets.token_urlsafe(24)

            session = requests.Session()

            session.proxies.update(TOR_PROXY)

            REMOTE_SESSIONS[sid] = session

            created = True

            if len(REMOTE_SESSIONS) > MAX_REMOTE_SESSIONS:
                first = next(iter(REMOTE_SESSIONS))

                if first != sid:
                    REMOTE_SESSIONS.pop(first, None)

        session = REMOTE_SESSIONS[sid]

    return session, sid, created


def attach_session_cookie(response, sid, created):
    if created:
        response.set_cookie(
            "proxy_sid",
            sid,
            httponly=True,
            samesite="Lax",
            max_age=60 * 60 * 12,
        )

    return response


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

<title>Tor Browser Proxy</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;

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

    padding: 14vh 20px 40px;
}

h1 {
    font-weight: 400;
    color: #7ee787;
    letter-spacing: .04em;
}

form {
    display: flex;
    width: 100%;
    max-width: 760px;
    gap: 8px;
}

input {
    flex: 1;

    background: #161b22;

    border: 1px solid #30363d;

    color: #e6edf3;

    padding: .8rem 1rem;

    border-radius: 6px;

    font: inherit;
}

button {
    background: #238636;

    border: 0;

    color: white;

    padding: .8rem 1.3rem;

    border-radius: 6px;

    font: inherit;

    cursor: pointer;
}

button:hover {
    background: #2ea043;
}

.info {
    color: #8b949e;

    margin-top: 2rem;

    max-width: 760px;

    text-align: center;

    line-height: 1.7;

    font-size: .85rem;
}

.status {
    color: #7ee787;

    margin-top: 1.5rem;

    font-size: .8rem;
}

</style>

</head>

<body>

<h1>tor browser proxy</h1>

<form action="/go" method="get">

<input
    name="q"
    placeholder="search or enter a website"
    autocomplete="off"
    autofocus
>

<button type="submit">
go
</button>

</form>

<div class="info">

Normal text searches Brave through Tor.

<br><br>

Examples:

<br>

minecraft servers

<br>

youtube.com minecraft

<br>

google.com linux

<br>

https://example.com

</div>

<div class="status">
server traffic → Tor
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
# SECURITY CHECK
# ============================================================

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
# CREATE A LOCAL /proxy URL
# ============================================================

def proxy_url(target):
    parsed = urlsplit(target)

    fragment = parsed.fragment

    clean = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.query,
            "",
        )
    )

    result = "/proxy?url=" + quote(
        clean,
        safe="",
    )

    if fragment:
        result += "#" + quote(
            fragment,
            safe="",
        )

    return result


# ============================================================
# ADD FORM QUERY PARAMETERS TO REMOTE URL
# ============================================================

def merge_query_parameters(target):
    extra = []

    for key in request.args:
        if key == "url":
            continue

        for value in request.args.getlist(key):
            extra.append((key, value))

    if not extra:
        return target

    parsed = urlsplit(target)

    existing = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    query = urlencode(
        existing + extra,
        doseq=True,
    )

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            query,
            parsed.fragment,
        )
    )


# ============================================================
# HEADERS SENT TO DESTINATION
# ============================================================

def destination_headers():
    headers = {
        "User-Agent": USER_AGENT,

        "Accept":
            request.headers.get(
                "Accept",
                "*/*",
            ),

        "Accept-Language":
            request.headers.get(
                "Accept-Language",
                "en-US,en;q=0.9",
            ),

        "Accept-Encoding": "identity",
    }

    for name in (
        "Content-Type",
        "Range",
        "If-Range",
        "If-None-Match",
        "If-Modified-Since",
    ):
        value = request.headers.get(name)

        if value:
            headers[name] = value

    return headers


# ============================================================
# FETCH THROUGH TOR
# ============================================================

def fetch_through_tor(
    session,
    target,
    method="GET",
    body=None,
):
    current = target

    current_method = method
    current_body = body

    for _ in range(MAX_REDIRECTS + 1):
        if not safe_target(current):
            raise requests.RequestException(
                "blocked destination"
            )

        response = session.request(
            current_method,
            current,

            data=current_body,

            headers=destination_headers(),

            timeout=(12, 60),

            allow_redirects=False,

            stream=True,
        )

        if response.status_code in (
            301,
            302,
            303,
            307,
            308,
        ):
            location = response.headers.get(
                "Location"
            )

            status = response.status_code

            response.close()

            if not location:
                raise requests.RequestException(
                    "redirect without Location"
                )

            current = urljoin(
                current,
                location,
            )

            if (
                status in (301, 302, 303)
                and current_method not in ("GET", "HEAD")
            ):
                current_method = "GET"
                current_body = None

            continue

        response.final_url = current

        return response

    raise requests.RequestException(
        "too many redirects"
    )


# ============================================================
# CSS URL REWRITING
# ============================================================

CSS_URL = re.compile(
    r"url\(\s*(['\"]?)(.*?)\1\s*\)",
    re.IGNORECASE,
)

CSS_IMPORT = re.compile(
    r"@import\s+(['\"])(.*?)\1",
    re.IGNORECASE,
)


def rewrite_css(css, base_url):
    def replace_url(match):
        value = match.group(2).strip()

        if value.startswith(
            (
                "data:",
                "blob:",
                "#",
            )
        ):
            return match.group(0)

        absolute = urljoin(
            base_url,
            value,
        )

        if not safe_target(absolute):
            return "url('')"

        return (
            "url('"
            + proxy_url(absolute)
            + "')"
        )

    def replace_import(match):
        value = match.group(2).strip()

        absolute = urljoin(
            base_url,
            value,
        )

        if not safe_target(absolute):
            return "@import ''"

        return (
            "@import '"
            + proxy_url(absolute)
            + "'"
        )

    css = CSS_URL.sub(
        replace_url,
        css,
    )

    css = CSS_IMPORT.sub(
        replace_import,
        css,
    )

    return css


# ============================================================
# NORMAL URL ATTRIBUTE REWRITING
# ============================================================

def rewrite_url(value, base_url):
    if not value:
        return value

    value = value.strip()

    if value.startswith(
        (
            "#",
            "data:",
            "blob:",
            "javascript:",
            "mailto:",
            "tel:",
        )
    ):
        return value

    absolute = urljoin(
        base_url,
        value,
    )

    if not safe_target(absolute):
        return "#"

    return proxy_url(absolute)


def rewrite_srcset(value, base_url):
    output = []

    for entry in value.split(","):
        entry = entry.strip()

        if not entry:
            continue

        pieces = entry.split()

        source = pieces[0]

        descriptor = " ".join(
            pieces[1:]
        )

        if source.startswith(
            (
                "data:",
                "blob:",
            )
        ):
            new_source = source

        else:
            absolute = urljoin(
                base_url,
                source,
            )

            if not safe_target(absolute):
                continue

            new_source = proxy_url(
                absolute
            )

        if descriptor:
            output.append(
                new_source
                + " "
                + descriptor
            )
        else:
            output.append(
                new_source
            )

    return ", ".join(output)


# ============================================================
# JAVASCRIPT NETWORK HOOK
#
# Helps redirect dynamically generated requests back through
# /proxy rather than directly to the remote website.
# ============================================================

def javascript_hook(base_url):
    escaped_base = (
        base_url
        .replace("\\", "\\\\")
        .replace("'", "\\'")
    )

    return f"""
<script>
(() => {{

const remoteBase = '{escaped_base}';


function torURL(value) {{

    if (
        value === null
        ||
        value === undefined
    ) {{
        return value;
    }}

    let text = String(value);


    if (
        text.startsWith('#')
        ||
        text.startsWith('data:')
        ||
        text.startsWith('blob:')
        ||
        text.startsWith('javascript:')
        ||
        text.startsWith('mailto:')
        ||
        text.startsWith('tel:')
    ) {{
        return text;
    }}


    if (
        text.startsWith('/proxy?')
        ||
        text.startsWith('/go?')
    ) {{
        return text;
    }}


    try {{

        let absolute =
            new URL(
                text,
                remoteBase
            ).href;


        if (
            !absolute.startsWith('http://')
            &&
            !absolute.startsWith('https://')
        ) {{
            return text;
        }}


        return (
            '/proxy?url='
            +
            encodeURIComponent(
                absolute
            )
        );

    }}

    catch (_) {{
        return text;
    }}
}}


/*
 * fetch()
 */

const nativeFetch =
    window.fetch;


if (nativeFetch) {{

    window.fetch =
        function(resource, options) {{

            if (
                resource
                instanceof Request
            ) {{

                resource =
                    new Request(

                        torURL(
                            resource.url
                        ),

                        resource
                    );

            }}

            else {{

                resource =
                    torURL(
                        resource
                    );
            }}


            return nativeFetch.call(
                this,
                resource,
                options
            );
        };
}}


/*
 * XMLHttpRequest
 */

const nativeOpen =
    XMLHttpRequest.prototype.open;


XMLHttpRequest.prototype.open =
    function(
        method,
        url,
        ...args
    ) {{

        return nativeOpen.call(
            this,
            method,
            torURL(url),
            ...args
        );
    };


/*
 * Prevent new tabs.
 */

window.open =
    function(url) {{

        if (url) {{
            window.location.href =
                torURL(url);
        }}

        return window;
    };


/*
 * Same-tab navigation.
 */

document.addEventListener(

    'click',

    function(event) {{

        const link =
            event.target.closest
            ?
            event.target.closest(
                'a[href]'
            )
            :
            null;


        if (!link) {{
            return;
        }}


        const href =
            link.getAttribute(
                'href'
            );


        if (
            !href
            ||
            href.startsWith('#')
            ||
            href.startsWith(
                'javascript:'
            )
        ) {{
            return;
        }}


        event.preventDefault();


        window.location.href =
            torURL(href);

    }},

    true
);


/*
 * Rewrite elements created dynamically.
 */

function fixElement(element) {{

    if (
        !element
        ||
        !element.getAttribute
    ) {{
        return;
    }}


    for (
        const attribute
        of
        [
            'href',
            'src',
            'poster',
            'data-src'
        ]
    ) {{

        let value =
            element.getAttribute(
                attribute
            );


        if (value) {{

            element.setAttribute(

                attribute,

                torURL(value)
            );
        }}
    }}


    element.removeAttribute(
        'target'
    );
}


const observer =
    new MutationObserver(

        function(changes) {{

            for (
                const change
                of changes
            ) {{

                if (
                    change.type
                    ===
                    'attributes'
                ) {{

                    fixElement(
                        change.target
                    );
                }}


                for (
                    const node
                    of
                    change.addedNodes
                ) {{

                    if (
                        node.nodeType
                        !== 1
                    ) {{
                        continue;
                    }}


                    fixElement(node);


                    if (
                        node.querySelectorAll
                    ) {{

                        node.querySelectorAll(
                            '[href],'
                            +
                            '[src],'
                            +
                            '[poster],'
                            +
                            '[data-src]'
                        )
                        .forEach(
                            fixElement
                        );
                    }}
                }}
            }}
        }}
    );


observer.observe(

    document.documentElement,

    {{
        childList: true,
        subtree: true,

        attributes: true,

        attributeFilter: [
            'href',
            'src',
            'poster',
            'data-src',
            'target'
        ]
    }}
);

}})();
</script>
"""


# ============================================================
# HTML REWRITING
# ============================================================

def rewrite_html(html, base_url):
    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    # Remove <base>, because it could bypass our rewritten URLs.
    for tag in soup.find_all("base"):
        tag.decompose()

    # Remove remote CSP/meta refresh.
    for meta in soup.find_all("meta"):
        value = (
            meta.get(
                "http-equiv",
                "",
            ).lower()
        )

        if value in (
            "content-security-policy",
            "refresh",
        ):
            meta.decompose()

    # General attributes.
    for tag in soup.find_all(True):
        tag.attrs.pop(
            "integrity",
            None,
        )

        tag.attrs.pop(
            "crossorigin",
            None,
        )

        tag.attrs.pop(
            "nonce",
            None,
        )

        # No new tabs.
        tag.attrs.pop(
            "target",
            None,
        )

        if "style" in tag.attrs:
            tag["style"] = rewrite_css(
                tag["style"],
                base_url,
            )

    # <style>
    for style in soup.find_all("style"):
        if style.string:
            style.string.replace_with(
                rewrite_css(
                    style.string,
                    base_url,
                )
            )

    attributes = {
        "a": "href",
        "area": "href",
        "link": "href",
        "script": "src",
        "img": "src",
        "iframe": "src",
        "source": "src",
        "video": "src",
        "audio": "src",
        "track": "src",
    }

    for tag_name, attribute in attributes.items():
        for tag in soup.find_all(
            tag_name
        ):
            value = tag.get(
                attribute
            )

            if value:
                tag[attribute] = rewrite_url(
                    value,
                    base_url,
                )

    # Responsive images.
    for tag in soup.find_all(
        ["img", "source"]
    ):
        value = tag.get("srcset")

        if value:
            tag["srcset"] = rewrite_srcset(
                value,
                base_url,
            )

    # Video posters.
    for video in soup.find_all("video"):
        poster = video.get(
            "poster"
        )

        if poster:
            video["poster"] = rewrite_url(
                poster,
                base_url,
            )

    # Common lazy-loaded content.
    for tag in soup.find_all(True):
        value = tag.get(
            "data-src"
        )

        if value:
            tag["data-src"] = rewrite_url(
                value,
                base_url,
            )

    # Forms.
    for form in soup.find_all("form"):
        action = (
            form.get("action")
            or base_url
        )

        action = urljoin(
            base_url,
            action,
        )

        method = (
            form.get(
                "method",
                "get",
            ).lower()
        )

        form.attrs.pop(
            "target",
            None,
        )

        if method == "get":
            form["action"] = "/proxy"

            hidden = soup.new_tag(
                "input"
            )

            hidden["type"] = "hidden"
            hidden["name"] = "url"
            hidden["value"] = action

            form.insert(
                0,
                hidden,
            )

        else:
            form["action"] = proxy_url(
                action
            )

    # Ensure head exists.
    if soup.head is None:
        head = soup.new_tag(
            "head"
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

    head = soup.head

    # Prevent direct network connections from page content.
    csp = soup.new_tag(
        "meta"
    )

    csp["http-equiv"] = (
        "Content-Security-Policy"
    )

    csp["content"] = (
        "default-src 'self' data: blob:; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self' data:; "
        "media-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-src 'self'; "
        "worker-src 'self' blob:; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self';"
    )

    head.insert(
        0,
        csp,
    )

    # Inject hook before most remote JavaScript runs.
    helper = BeautifulSoup(
        javascript_hook(
            base_url
        ),
        "html.parser",
    )

    if helper.script:
        head.insert(
            1,
            helper.script,
        )

    return str(soup)


# ============================================================
# BUFFER TEXT RESPONSES
# ============================================================

def read_remote_response(remote):
    data = bytearray()

    for chunk in remote.iter_content(
        chunk_size=65536
    ):
        if not chunk:
            continue

        data.extend(chunk)

        if len(data) > MAX_REWRITE_SIZE:
            remote.close()

            raise requests.RequestException(
                "page too large to rewrite"
            )

    remote.close()

    return bytes(data)


# ============================================================
# RETURN REMOTE FILES / VIDEO / IMAGES
# ============================================================

def stream_remote(
    remote,
    sid,
    created,
):
    def generate():
        try:
            for chunk in remote.iter_content(
                chunk_size=65536
            ):
                if chunk:
                    yield chunk
        finally:
            remote.close()

    headers = {}

    for name in (
        "Content-Type",
        "Content-Length",
        "Content-Range",
        "Accept-Ranges",
        "Cache-Control",
        "ETag",
        "Last-Modified",
    ):
        value = remote.headers.get(name)

        if value:
            headers[name] = value

    headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    result = Response(
        generate(),
        status=remote.status_code,
        headers=headers,
        direct_passthrough=True,
    )

    return attach_session_cookie(
        result,
        sid,
        created,
    )


# ============================================================
# MAIN PROXY
# ============================================================

@app.route(
    "/proxy",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
    ],
)
def proxy():
    target = request.args.get(
        "url",
        "",
    ).strip()

    if not target:
        return Response(
            "missing URL",
            status=400,
            mimetype="text/plain",
        )

    if request.method == "GET":
        target = merge_query_parameters(
            target
        )

    if not safe_target(target):
        return Response(
            "bad or blocked URL",
            status=400,
            mimetype="text/plain",
        )

    remote_session, sid, created = (
        get_remote_session()
    )

    body = None

    if request.method not in (
        "GET",
        "HEAD",
    ):
        body = request.get_data()

    try:
        remote = fetch_through_tor(
            remote_session,
            target,
            request.method,
            body,
        )

    except requests.RequestException as error:
        result = Response(
            "Tor request failed:\n\n"
            + str(error),
            status=502,
            mimetype="text/plain",
        )

        return attach_session_cookie(
            result,
            sid,
            created,
        )

    content_type = (
        remote.headers.get(
            "Content-Type",
            "",
        ).lower()
    )

    # HTML
    if (
        "text/html" in content_type
        or
        "application/xhtml+xml"
        in content_type
    ):
        try:
            raw = read_remote_response(
                remote
            )

        except requests.RequestException as error:
            return Response(
                str(error),
                status=502,
            )

        encoding = (
            remote.encoding
            or "utf-8"
        )

        text = raw.decode(
            encoding,
            errors="replace",
        )

        text = rewrite_html(
            text,
            remote.final_url,
        )

        result = Response(
            text,
            status=remote.status_code,
            content_type=(
                "text/html; charset=utf-8"
            ),
        )

        result.headers[
            "Referrer-Policy"
        ] = "no-referrer"

        return attach_session_cookie(
            result,
            sid,
            created,
        )

    # CSS
    if "text/css" in content_type:
        raw = read_remote_response(
            remote
        )

        text = raw.decode(
            remote.encoding or "utf-8",
            errors="replace",
        )

        text = rewrite_css(
            text,
            remote.final_url,
        )

        result = Response(
            text,
            status=remote.status_code,
            content_type=(
                "text/css; charset=utf-8"
            ),
        )

        return attach_session_cookie(
            result,
            sid,
            created,
        )

    # Other resources are streamed.
    return stream_remote(
        remote,
        sid,
        created,
    )


# ============================================================
# TURN USER INPUT INTO A DESTINATION
# ============================================================

def input_to_target(text):
    text = text.strip()

    if text.startswith(
        (
            "http://",
            "https://",
        )
    ):
        return text

    first, separator, rest = (
        text.partition(" ")
    )

    if separator and rest:
        candidate = (
            first.lower()
            .replace(
                "https://",
                "",
            )
            .replace(
                "http://",
                "",
            )
            .split("/")[0]
        )

        if candidate in ENDPOINTS:
            return (
                ENDPOINTS[
                    candidate
                ]
                .format(
                    quote_plus(
                        rest.strip()
                    )
                )
            )

    # If it's just a domain, browse to it.
    if " " not in text:
        hostname = text.split("/")[0]

        if "." in hostname:
            return (
                "https://"
                + text
            )

    # Otherwise perform default Brave search.
    return (
        ENDPOINTS[
            DEFAULT_ENGINE
        ]
        .format(
            quote_plus(text)
        )
    )


# ============================================================
# SEARCH / URL BAR
# ============================================================

@app.route("/go")
def go():
    q = request.args.get(
        "q",
        "",
    ).strip()

    if not q:
        return redirect("/")

    target = input_to_target(q)

    if not safe_target(target):
        return Response(
            "bad or blocked URL",
            status=400,
        )

    return redirect(
        proxy_url(target)
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
