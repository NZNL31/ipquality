"""ipquality 在 Windows / Git Bash 下的依赖兼容层。

为 IPQuality 脚本提供 dig / nc / bc / ss 的最小可用实现，
语义按脚本实际调用方式实现，而非完整复刻原工具。
"""

import json
import os
import socket
import subprocess
import sys
import time
from decimal import Decimal, ROUND_DOWN, getcontext, localcontext

getcontext().prec = 60

HERE = os.path.dirname(os.path.abspath(__file__))
NS_CACHE = os.path.join(HERE, ".ns_cache.json")
NS_TTL = 1800  # 30 分钟内复用已优选域名服务器

DNS_TYPES = {
    "A", "AAAA", "MX", "TXT", "NS", "CNAME", "PTR", "SOA", "CAA", "SRV", "ANY",
}


# --------------------------------------------------------------------------
# dig
# --------------------------------------------------------------------------

def _probe_nameservers(candidates, timeout=1.2):
    """并发探测，返回首个可用且最快的域名服务器。"""
    import threading

    results = []
    lock = threading.Lock()

    def probe(ns):
        try:
            import dns.message
            import dns.query

            q = dns.message.make_query("example.com", "A")
            dns.query.udp(q, ns, timeout=timeout)
            with lock:
                results.append(ns)
        except Exception:
            pass

    threads = [threading.Thread(target=probe, args=(ns,), daemon=True)
               for ns in candidates]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 0.5)
    return results[0] if results else None


def _system_nameservers():
    try:
        import dns.resolver

        return list(dns.resolver.Resolver().nameservers)
    except Exception:
        return []


def _best_nameservers():
    try:
        with open(NS_CACHE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if time.time() - data.get("ts", 0) < NS_TTL and data.get("ns"):
            return data["ns"]
    except Exception:
        pass

    candidates = [str(ns) for ns in _system_nameservers()]
    best = _probe_nameservers(candidates) if candidates else None
    chosen = [best] if best else candidates[:1]
    if not chosen:
        chosen = ["223.5.5.5"]
    try:
        with open(NS_CACHE, "w", encoding="utf-8") as fh:
            json.dump({"ts": time.time(), "ns": chosen}, fh)
    except Exception:
        pass
    return chosen


def _make_resolver(lifetime):
    import dns.resolver

    r = dns.resolver.Resolver(configure=False)
    r.nameservers = _best_nameservers()
    r.timeout = min(2.0, lifetime)
    r.lifetime = lifetime
    r.retry_servfail = False
    return r


def _resolve(name, qtype, lifetime):
    import dns.resolver

    resolver = _make_resolver(lifetime)
    try:
        ans = resolver.resolve(name, qtype, raise_on_no_answer=False)
        if ans.rrset is None:
            return [], "NOERROR"
        return [rr for rr in ans], "NOERROR"
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "NOERROR"
    except dns.resolver.NoNameservers:
        return [], "SERVFAIL"
    except Exception:
        return [], "TIMEOUT"


def _short_form(rr, qtype):
    if qtype in ("A", "AAAA"):
        return rr.address
    if qtype == "MX":
        return "%d %s" % (rr.preference, rr.exchange)
    if qtype == "TXT":
        return "".join(
            s.decode("utf-8", "replace") if isinstance(s, bytes) else str(s)
            for s in rr.strings
        )
    if qtype == "CNAME":
        return str(rr.target)
    if qtype == "NS":
        return str(rr.target)
    if qtype == "PTR":
        return str(rr.target)
    return str(rr)


def dig_main(argv):
    name = None
    qtype = None
    short = False
    lifetime = 3.0
    reverse = False

    for arg in argv:
        if arg in ("-v", "-V", "--version"):
            sys.stdout.write("diG 9.18.24 (windows-compat shim)\n")
            return 0
        if arg.startswith("+"):
            low = arg.lower()
            if low == "+short":
                short = True
            elif low.startswith("+time="):
                try:
                    lifetime = float(low.split("=", 1)[1])
                except ValueError:
                    pass
            elif low in ("+tc", "+tcp"):
                pass
            continue
        if arg.startswith("@"):
            continue
        if arg in ("-4", "-6", "-x"):
            reverse = arg == "-x"
            continue
        if arg.upper() in DNS_TYPES and name is not None:
            qtype = arg.upper()
            continue
        if arg.upper() in DNS_TYPES and qtype is None and name is None:
            qtype = arg.upper()
            continue
        if name is None:
            name = arg

    if reverse and name:
        try:
            import ipaddress

            name = ipaddress.ip_address(name).reverse_pointer
        except Exception:
            pass
    if not name:
        sys.stderr.write("dig: missing query name\n")
        return 9

    qtype = qtype or "A"
    records, status = _resolve(name, qtype, max(1.0, lifetime))

    if short:
        for rr in records:
            sys.stdout.write(_short_form(rr, qtype) + "\n")
        return 0 if status != "TIMEOUT" else 9

    out = []
    out.append("; <<>> DiG 9.18.24-compat <<>> %s %s" % (name, qtype))
    out.append(";; global options: +cmd")
    out.append(";; Got answer:")
    out.append(
        ";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d"
        % (status, os.getpid() % 65535)
    )
    out.append(
        ";; flags: qr rd ra; QUERY: 1, ANSWER: %d, AUTHORITY: 0, ADDITIONAL: 0"
        % len(records)
    )
    out.append("")
    if records:
        out.append(";; ANSWER SECTION:")
        for rr in records:
            out.append("%s. 60 IN %s %s" % (name.rstrip("."), qtype,
                                            _short_form(rr, qtype)))
        out.append("")
    sys.stdout.write("\n".join(out) + "\n")
    return 0


# --------------------------------------------------------------------------
# nc
# --------------------------------------------------------------------------

def nc_main(argv):
    timeout = 3.0
    zero_scan = False
    positional = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            sys.stdout.write("nc (windows-compat shim): usage nc [-s src] [-p sport] "
                             "[-w timeout] [-z] host port\n")
            return 0
        if arg.startswith("-") and len(arg) > 1:
            flags = arg[1:]
            j = 0
            while j < len(flags):
                flag = flags[j]
                if flag in ("s", "p", "w", "i", "o", "q"):
                    rest = flags[j + 1:]
                    if rest:
                        value = rest
                    elif i + 1 < len(argv):
                        i += 1
                        value = argv[i]
                    else:
                        value = ""
                    if flag == "w":
                        try:
                            timeout = float(value)
                        except ValueError:
                            pass
                    j = len(flags)
                    continue
                if flag == "z":
                    zero_scan = True
                j += 1
            i += 1
            continue
        positional.append(arg)
        i += 1

    if len(positional) < 2:
        sys.stderr.write("nc: missing host/port\n")
        return 1
    host, port = positional[0], positional[1]
    try:
        port = int(port)
    except ValueError:
        sys.stderr.write("nc: bad port\n")
        return 1

    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        sys.stderr.write("nc: cannot resolve %s (%s)\n" % (host, exc))
        return 1
    if not infos:
        return 1
    family, socktype, proto, _, addr = infos[0]

    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    try:
        sock.connect(addr)
    except Exception as exc:
        sys.stderr.write("nc: connect to %s port %d failed: %s\n"
                         % (host, port, exc))
        return 1

    if zero_scan:
        sock.close()
        return 0

    payload = b""
    if not sys.stdin.isatty():
        try:
            payload = sys.stdin.buffer.read()
        except Exception:
            payload = b""

    chunks = []
    # 先读服务端主动 banner（SMTP 等协议在客户端发言前先返回 220）
    try:
        sock.settimeout(min(2.0, timeout))
        first = sock.recv(4096)
        if first:
            chunks.append(first)
    except Exception:
        pass

    if payload:
        try:
            sock.sendall(payload)
        except Exception:
            pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock.settimeout(max(0.2, deadline - time.time()))
            data = sock.recv(4096)
        except Exception:
            break
        if not data:
            break
        chunks.append(data)
        if b"\n" in data and sum(len(c) for c in chunks) > 0:
            # 已获得响应内容，连接仍未关闭时短暂等待即可
            break

    sock.close()
    if chunks:
        sys.stdout.write(b"".join(chunks).decode("utf-8", "replace"))
        if not sys.stdout.isatty():
            pass
    return 0


# --------------------------------------------------------------------------
# bc
# --------------------------------------------------------------------------

class _Num:
    __slots__ = ("value", "scale")

    def __init__(self, value, scale):
        self.value = value
        self.scale = scale


class _BcParser:
    """极简 bc 表达式求值器，覆盖 IPQuality 使用的运算形式。"""

    def __init__(self, text, global_scale):
        self.text = text
        self.pos = 0
        self.global_scale = global_scale

    def parse(self):
        result = self.expr()
        self.skip_ws()
        if self.pos < len(self.text):
            raise ValueError("trailing input: %r" % self.text[self.pos:])
        return result

    def skip_ws(self):
        while self.pos < len(self.text) and self.text[self.pos] in " \t":
            self.pos += 1

    def peek(self):
        self.skip_ws()
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _match(self, token):
        self.skip_ws()
        if self.text.startswith(token, self.pos):
            self.pos += len(token)
            return True
        return False

    def expr(self):
        left = self.term()
        while True:
            ch = self.peek()
            if ch == "+":
                self.pos += 1
                left = self._add(left, self.term(), 1)
            elif ch == "-":
                self.pos += 1
                left = self._add(left, self.term(), -1)
            else:
                return left

    def term(self):
        left = self.power()
        while True:
            ch = self.peek()
            if ch == "*":
                self.pos += 1
                left = self._mul(left, self.power())
            elif ch == "/":
                self.pos += 1
                left = self._div(left, self.power())
            elif ch == "%":
                self.pos += 1
                left = self._mod(left, self.power())
            else:
                return left

    def power(self):
        base = self.unary()
        if self.peek() == "^":
            self.pos += 1
            exp = self.power()
            with localcontext() as ctx:
                ctx.prec = 60
                value = base.value ** int(exp.value)
            return _Num(value, self.global_scale)
        return base

    def unary(self):
        ch = self.peek()
        if ch == "-":
            self.pos += 1
            val = self.unary()
            return _Num(-val.value, val.scale)
        if ch == "+":
            self.pos += 1
            return self.unary()
        if ch == "(":
            self.pos += 1
            val = self.expr()
            self.skip_ws()
            if self.peek() == ")":
                self.pos += 1
            return val
        return self.compare()

    def compare(self):
        left = self.primary()
        for op in ("<=", ">=", "!=", "==", "<", ">"):
            if self._match(op):
                right = self.primary()
                res = {
                    "<=": left.value <= right.value,
                    ">=": left.value >= right.value,
                    "!=": left.value != right.value,
                    "==": left.value == right.value,
                    "<": left.value < right.value,
                    ">": left.value > right.value,
                }[op]
                return _Num(Decimal(1 if res else 0), 0)
        return left

    def primary(self):
        self.skip_ws()
        start = self.pos
        while self.pos < len(self.text) and (
            self.text[self.pos].isdigit() or self.text[self.pos] == "."
        ):
            self.pos += 1
        if start == self.pos:
            raise ValueError("unexpected char %r" % self.text[self.pos:self.pos + 1])
        literal = self.text[start:self.pos]
        scale = len(literal.split(".")[1]) if "." in literal else 0
        return _Num(Decimal(literal), scale)

    # --- 运算语义（近似 GNU bc） ---
    def _add(self, a, b, sign):
        scale = max(a.scale, b.scale)
        value = a.value + b.value * sign
        return _Num(value, scale)

    def _mul(self, a, b):
        scale = min(a.scale + b.scale, max(self.global_scale, a.scale, b.scale))
        with localcontext() as ctx:
            ctx.prec = 60
            value = (a.value * b.value).quantize(Decimal(1).scaleb(-scale),
                                                 rounding=ROUND_DOWN)
        return _Num(value, scale)

    def _div(self, a, b):
        scale = self.global_scale
        if b.value == 0:
            raise ValueError("divide by zero")
        with localcontext() as ctx:
            ctx.prec = 60
            value = (a.value / b.value).quantize(Decimal(1).scaleb(-scale),
                                                 rounding=ROUND_DOWN)
        return _Num(value, scale)

    def _mod(self, a, b):
        scale = max(a.scale, b.scale)
        with localcontext() as ctx:
            ctx.prec = 60
            value = a.value % b.value
        return _Num(value, scale)


def _format_num(num):
    if num.scale <= 0:
        return str(num.value.quantize(Decimal(1), rounding=ROUND_DOWN))
    quant = Decimal(1).scaleb(-num.scale)
    return str(num.value.quantize(quant, rounding=ROUND_DOWN))


def bc_main(argv):
    if "--version" in argv or "-v" in argv:
        sys.stdout.write("bc 1.07.1 (windows-compat shim)\n")
        return 0

    global_scale = 20 if "-l" in argv else 0
    script = sys.stdin.read()
    outputs = []
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("scale"):
            parts = line.split("=")
            if len(parts) == 2:
                try:
                    global_scale = int(parts[1].strip())
                except ValueError:
                    pass
            continue
        if line in ("quit", "q"):
            break
        try:
            num = _BcParser(line, global_scale).parse()
            outputs.append(_format_num(num))
        except Exception:
            outputs.append("")
    sys.stdout.write("\n".join(outputs) + ("\n" if outputs else ""))
    return 0


# --------------------------------------------------------------------------
# ss（脚本仅用 ss -tano | grep -q ":25" 判断本地 25 端口占用）
# --------------------------------------------------------------------------

def ss_main(argv):
    """只输出本地端口为 25 的连接行。

    脚本用 `ss -tano | grep -q ":25"` 判断本地 25 端口是否被占用；
    netstat 原始输出会把远端 :25 也算进来，必须按本地地址列过滤。
    """
    local_only = True
    wanted_ports = set()
    for token in argv:
        if token.startswith("sport") or token.startswith("dport"):
            for part in token.replace("=", " ").split():
                if part.isdigit():
                    wanted_ports.add(part)
    if not wanted_ports:
        wanted_ports = {"25"}

    try:
        proc = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                              timeout=10, errors="replace")
    except Exception:
        return 0

    out = []
    for line in proc.stdout.splitlines():
        cols = line.split()
        if len(cols) < 2 or cols[0].upper() not in ("TCP", "UDP"):
            continue
        local = cols[1]
        port = local.rsplit(":", 1)[-1]
        if wanted_ports and port not in wanted_ports:
            continue
        out.append(line)
    if out:
        sys.stdout.write("\n".join(out) + "\n")
    return 0
