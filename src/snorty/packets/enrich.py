"""One line that says what a packet is for, from the names it carries. Pure."""

from snorty.packets.models import PacketView


def _clean(text: str) -> str:
    return "".join(c if c.isprintable() else "?" for c in text)


def hint(view: PacketView) -> str | None:
    """ "DNS lookup: x", "TLS to x" or "HTTP GET x/path"; None when the packet names nothing."""
    names = {key: _clean(value) for key, value in view.hints if value}
    if name := names.get("dns.qry.name"):
        return f"DNS lookup: {name}"
    if name := names.get("tls.handshake.extensions_server_name"):
        return f"TLS to {name}"
    if host := names.get("http.host"):
        method = names.get("http.request.method", "HTTP")
        return f"{method} {host}{names.get('http.request.uri', '')}"
    return None
