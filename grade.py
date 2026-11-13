#!/usr/bin/env python3
import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from urllib import request, error
from urllib.parse import urlparse
from typing import List, Tuple, Dict, Optional

# Requires: psutil (pip install psutil)
import psutil
import re

# ---------- Filenames (stored under --artifacts-dir) ----------
REF_FILE = "ref_index.html"
PROXY_FILE = "proxy_index.html"
PROXY_FILE_2 = "proxy_index_cached.html"
PROXY_FILE_3 = "proxy_index_after_ttl.html"
PROXY_LOG = "proxy.log"
BLOCKLIST_FILENAME = "blocklist"
REF_PREFETCH_FILES = ["ref_text1.txt", "ref_apple_ex.png"]
PROXY_PREFETCH_FILES = ["proxy_text1_blocked.txt", "proxy_apple_ex_blocked.png"]

# Prefetch test URLs
PREFETCH_URLS = [
    "http://netsys.cs.colorado.edu/files/text1.txt",
    "http://netsys.cs.colorado.edu/images/apple_ex.png",
]

# Default blocklist content created in cwd (students read from CWD)
BLOCKLIST_CONTENT = "www.google.com\nmail.yahoo.com\n157.240.28.35\n"

# ---------- Pretty printing ----------
def print_header(title: str):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

# ---------- Root requirement ----------
def require_root_or_exit():
    if hasattr(os, "geteuid"):
        if os.geteuid() != 0:
            print_header("Insufficient privileges")
            print("✖ This grading script must be run as root (required for iptables origin blocking).")
            print("  Try: sudo ./grade_proxy.py [args]")
            sys.exit(1)
    else:
        print_header("Unsupported platform")
        print("✖ This environment does not support required root/iptables operations.")
        sys.exit(1)

# ---------- Setup steps ----------
def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def clear_cache(cache_dir: str):
    print_header(f"Step 1: Clearing cache directory: {cache_dir}")
    if os.path.isdir(cache_dir):
        for name in os.listdir(cache_dir):
            path = os.path.join(cache_dir, name)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
    else:
        os.makedirs(cache_dir, exist_ok=True)
    print("✔ Cache cleared.")

def write_blocklist(filename: str, content: str):
    print_header(f"Step 2: Re-initializing blocklist → {filename}")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    lines = [l for l in content.splitlines() if l.strip()]
    print(f"✔ Wrote blocklist with {len(lines)} entries.")

def run_make():
    print_header("Step 3: Building project with warnings suppressed")
    try:
        subprocess.run(["make", "clean"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    except FileNotFoundError:
        print("✖ make not found. Ensure build tools are installed.")
        sys.exit(1)

    env = os.environ.copy()
    env["CFLAGS"] = (env.get("CFLAGS", "") + " -w").strip()

    try:
        subprocess.run(["make", "-s"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, check=True)
        print("✔ Build completed.")
    except subprocess.CalledProcessError:
        print("✖ Build failed. (Compilation error even with warnings suppressed.)")
        sys.exit(1)

def kill_process_using_port(port: int):
    print_header(f"Step 3.5: Ensuring port {port} is free")
    killed_any = False
    for conn in psutil.net_connections(kind="inet"):
        try:
            if conn.laddr and conn.laddr.port == port:
                pid = conn.pid
                if pid:
                    try:
                        proc = psutil.Process(pid)
                        print(f"⚠ Port {port} in use by PID {pid} ({proc.name()}). Terminating...")
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except psutil.TimeoutExpired:
                            print(f"  ⏱ PID {pid} did not exit in time. Forcing kill.")
                            proc.kill()
                        print(f"✔ Freed port {port}.")
                        killed_any = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception:
            continue
    if not killed_any:
        print(f"✔ Port {port} is free.")

def wait_for_port(host: str, port: int, deadline_sec: float = 5.0, interval: float = 0.1) -> bool:
    end = time.time() + deadline_sec
    while time.time() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(interval)
            try:
                s.connect((host, port))
                return True
            except OSError:
                time.sleep(interval)
    return False

def start_proxy(port: int, cache_ttl: int, artifacts_dir: str):
    print_header(f"Step 4: Launching proxy: ./proxy {port} {cache_ttl}")
    if not os.path.exists("./proxy"):
        print("✖ ./proxy executable not found after build.")
        sys.exit(1)

    log_path = os.path.join(artifacts_dir, PROXY_LOG)
    logf = open(log_path, "wb")
    proc = subprocess.Popen(
        ["./proxy", str(port), str(cache_ttl)],
        stdout=logf,
        stderr=logf,
        preexec_fn=os.setsid  # start new process group
    )

    if not wait_for_port("127.0.0.1", port, deadline_sec=5.0):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        print("✖ Proxy failed to start or did not open the listening port in time.")
        print(f"  Check {log_path} for details.")
        sys.exit(1)

    print("✔ Proxy is up.")
    return proc

def stop_proxy(proc: subprocess.Popen):
    print_header("Shutting down proxy")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception as e:
        print(f"(Note) Issue while stopping proxy: {e}")
    print("✔ Proxy stopped.")

# ---------- Basic fetching ----------
def fetch_direct(url: str, out_path: str, timeout: float = 15.0) -> bytes:
    print_header(f"Step 5: Fetch reference page directly\nURL: {url}")
    try:
        with request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"✔ Saved direct fetch to {out_path} ({len(data)} bytes).")
        return data
    except error.URLError as e:
        print(f"✖ Direct fetch failed: {e}")
        sys.exit(1)

def fetch_via_proxy(url: str, proxy_host: str, proxy_port: int, out_path: str, timeout: float = 15.0) -> bytes:
    print_header(f"Step 6: Fetch via proxy\nProxy: {proxy_host}:{proxy_port}\nURL:   {url}")
    proxy_url = f"http://{proxy_host}:{proxy_port}"
    handler = request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = request.build_opener(handler)
    opener.addheaders = [("Connection", "close")]
    try:
        with opener.open(url, timeout=timeout) as resp:
            data = resp.read()
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"✔ Saved proxy fetch to {out_path} ({len(data)} bytes).")
        return data
    except error.HTTPError as e:
        body = e.read() or b""
        with open(out_path, "wb") as f:
            f.write(body)
        print(f"✖ Proxy fetch returned HTTP error {e.code}.")
        return b""
    except error.URLError as e:
        print(f"✖ Proxy fetch failed: {e}")
        return b""

def fetch_via_proxy_with_headers(url: str, proxy_host: str, proxy_port: int, timeout: float = 15.0) -> Tuple[int, bytes, Dict[str, str]]:
    proxy_url = f"http://{proxy_host}:{proxy_port}"
    handler = request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = request.build_opener(handler)
    opener.addheaders = [("Connection", "close")]
    try:
        with opener.open(url, timeout=timeout) as resp:
            code = getattr(resp, "status", 200)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read()
            return code, body, headers
    except error.HTTPError as e:
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        body = e.read() or b""
        return e.code, body, headers
    except error.URLError as e:
        return 0, b"", {"error": str(e.reason)}

# ---------- Blocklist helpers & test ----------
def urls_from_blocklist_entries(entries: List[str]) -> List[str]:
    urls = []
    for raw in entries:
        host = raw.strip()
        if not host or host.startswith("#"):
            continue
        if host.startswith("http://") or host.startswith("https://"):
            urls.append(host)
        else:
            urls.append(f"http://{host}/index.html")
    return urls

def http_get_via_proxy_raw(url: str, proxy_host: str, proxy_port: int, timeout: float = 8.0) -> Tuple[int, bytes, str]:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "http":
        return (0, b"", "Non-HTTP URL (HTTPS not supported for raw proxy grading)")
    req_line = f"GET {url} HTTP/1.1\r\n"
    headers = [f"Host: {parsed.netloc}", "Connection: close", "User-Agent: grading-script", "", ""]
    payload = (req_line + "\r\n".join(headers)).encode("ascii", errors="ignore")
    try:
        with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as s:
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)
            s.settimeout(timeout)
            chunks = []
            while True:
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    return (0, b"".join(chunks), "Timeout while reading response")
                if not data:
                    break
                chunks.append(data)
        raw = b"".join(chunks)
    except (OSError, socket.timeout) as e:
        return (0, b"", f"Socket error: {e}")
    try:
        head, _, _ = raw.partition(b"\r\n")
        status_line = head.decode("iso-8859-1", errors="replace")
        parts = status_line.split()
        code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        return (code, raw, status_line)
    except Exception:
        return (0, raw, "Malformed or missing status line")

def grade_forwarding(forwarding_ok: bool) -> int:
    print_header('Grading Test 1 — "Forwarding and Relaying Data" (60 pts)')
    points = 60 if forwarding_ok else 0
    if forwarding_ok:
        print("✔ Files match byte-for-byte. Awarding 60/60.")
    else:
        print("✖ Files differ. Awarding 0/60.")
        print(f"  You can diff '{REF_FILE}' vs '{PROXY_FILE}' to investigate.")
    return points

def check_blocked_via_proxy(url: str, proxy_host: str, proxy_port: int, timeout: float = 8.0) -> Tuple[bool, str]:
    code, _, status_line = http_get_via_proxy_raw(url, proxy_host, proxy_port, timeout=timeout)
    if code == 403:
        return (True, f"HTTP {code}")
    elif code == 0:
        return (False, status_line)
    else:
        return (False, f"HTTP {code}")

def test_blocklist(proxy_host: str, proxy_port: int, filename: str) -> Tuple[int, List[Tuple[str, bool, str]]]:
    print_header('Test 2 — "Access website in blocklist" (10 pts)')
    try:
        with open(filename, "r", encoding="utf-8") as f:
            entries = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"✖ Blocklist file '{filename}' not found.")
        return 0, []
    urls = urls_from_blocklist_entries(entries)
    results = []
    all_blocked = True
    for url in urls:
        blocked, detail = check_blocked_via_proxy(url, proxy_host, proxy_port)
        results.append((url, blocked, detail))
        status_str = "BLOCKED (403)" if blocked else f"FAILED ({detail})"
        print(f"  - {url} → {status_str}")
        if not blocked:
            all_blocked = False
    points = 10 if all_blocked and len(urls) > 0 else 0
    if points == 10:
        print("✔ All blocklisted sites correctly returned 403 via proxy. Awarding 10/10.")
    else:
        print("✖ One or more blocklisted sites did not return 403. Awarding 0/10.")
    return points, results

# ---------- Cache filesystem helpers (RELAXED MATCH) ----------
def extract_http_body_if_present(data: bytes) -> bytes:
    if data.startswith(b"HTTP/1."):
        head_sep = b"\r\n\r\n"
        alt_sep = b"\n\n"
        if head_sep in data:
            return data.split(head_sep, 1)[1]
        elif alt_sep in data:
            return data.split(alt_sep, 1)[1]
    return data

def read_file_safely(path: str, max_bytes: int = 32 * 1024 * 1024) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except Exception:
        return b""

_whitespace_re = re.compile(r"\s+")

def normalize_text(b: bytes) -> str:
    if not b:
        return ""
    for enc in ("utf-8", "latin-1"):
        try:
            s = b.decode(enc, errors="ignore")
            break
        except Exception:
            continue
    s = s.replace("\x00", "")
    s = _whitespace_re.sub(" ", s).strip()
    return s

def select_reference_lines(ref_text: str, max_lines: int = 10, min_len: int = 8) -> List[str]:
    raw_lines = [ln.strip() for ln in ref_text.splitlines()]
    chunks: List[str] = []
    for ln in raw_lines:
        for piece in re.split(r"[<>]", ln):
            piece = piece.strip()
            if len(piece) >= min_len:
                chunks.append(piece)
    seen = set()
    uniq = []
    for c in chunks:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq[:max_lines] if uniq else []

def count_line_matches(haystack: str, needles: List[str]) -> int:
    matches = 0
    for n in needles:
        if n and n in haystack:
            matches += 1
    return matches

def find_cached_file_relaxed(cache_dir: str, ref_body: bytes, min_matches: int = 3) -> Optional[Tuple[str, int]]:
    if not os.path.isdir(cache_dir):
        return None
    ref_text = normalize_text(ref_body)
    ref_snippets = select_reference_lines(ref_text, max_lines=12, min_len=8)
    best_path = None
    best_score = -1
    for root, _, files in os.walk(cache_dir):
        for fn in files:
            p = os.path.join(root, fn)
            data = read_file_safely(p)
            if not data:
                continue
            if data == ref_body:
                return (p, len(ref_snippets))
            body = extract_http_body_if_present(data)
            if body == ref_body:
                return (p, len(ref_snippets))
            cand_text = normalize_text(body)
            score = count_line_matches(cand_text, ref_snippets)
            if score > best_score:
                best_score = score
                best_path = p
    if best_path and best_score >= min_matches:
        return (best_path, best_score)
    return None

# ---------- iptables origin blocking ----------
def run_cmd(args: List[str]) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return (127, "", "command not found")

def resolve_host_ips(hostname: str, port: int = 80) -> List[str]:
    ips = []
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        pass
    return ips

def try_add_block_rules(origin_ips: List[str]) -> Tuple[bool, List[List[str]]]:
    if not origin_ips:
        print("(warn) Could not resolve origin IPs; cannot block.")
        return (False, [])
    rc, _, _ = run_cmd(["iptables", "--version"])
    if rc != 0:
        print("(warn) iptables not available; cannot enforce OS-level block.")
        return (False, [])
    rules_added: List[List[str]] = []
    ok_any = False
    for ip in origin_ips:
        rule = ["iptables", "-I", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", "80",
                "-j", "REJECT", "--reject-with", "tcp-reset"]
        rc, out, err = run_cmd(rule)
        if rc == 0:
            print(f"  (block) Added iptables rule to block TCP:80 to {ip}")
            rules_added.append(rule)
            ok_any = True
        else:
            print(f"  (warn) Failed to add iptables block for {ip}: {(err or out).strip()}")
    return (ok_any, rules_added)

def try_remove_block_rules(rules_added: List[List[str]]):
    for rule in reversed(rules_added):
        remove = rule.copy()
        try:
            idx = remove.index("-I")
            remove[idx] = "-D"
        except ValueError:
            pass
        rc, out, err = run_cmd(remove)
        if rc == 0:
            print("  (unblock) Removed iptables block")
        else:
            msg = (err or out).strip()
            if msg:
                print(f"  (note) Could not remove iptables rule: {msg}")

# ---------- Test 3a: Serve from cache while origin is blocked ----------
def test_cache_hit_block_origin(proxy_host: str, proxy_port: int,
                                url: str, ref_bytes: bytes,
                                cache_dir: str,
                                artifacts_dir: str) -> int:
    print_header('Test 3a — "Serve from cache while origin is blocked" (20 pts)')

    found = find_cached_file_relaxed(cache_dir, ref_bytes, min_matches=3)
    if not found:
        print("✖ Could not locate cached file for index.html in the cache directory (relaxed search).")
        return 0
    cached_path, matched_lines = found
    print(f"(info) Using cached file: {cached_path}  (matched lines: {matched_lines})")

    try:
        mtime_before = os.path.getmtime(cached_path)
    except FileNotFoundError:
        print("✖ Cached file disappeared unexpectedly.")
        return 0

    parsed = urlparse(url)
    origin_host = parsed.hostname or ""
    origin_ips = resolve_host_ips(origin_host, 80)
    blocked_ok, rules_added = try_add_block_rules(origin_ips)
    if not blocked_ok:
        print("✖ Failed to block origin via iptables. Cannot validate offline cache serving.")
        return 0

    try:
        code, body, headers = fetch_via_proxy_with_headers(url, proxy_host, proxy_port, timeout=15.0)
        out_path = os.path.join(artifacts_dir, PROXY_FILE_2)
        with open(out_path, "wb") as f:
            f.write(body or b"")

        if not (code == 200 and body == ref_bytes and len(body) > 0):
            print("✖ Cache-serve check failed: expected 200 and body to match reference while origin is blocked.")
            print(f"  status={code}, content_match={body == ref_bytes}")
            return 0

        try:
            mtime_after = os.path.getmtime(cached_path)
        except FileNotFoundError:
            print("✖ Cached file disappeared after request (unexpected).")
            return 0

        if mtime_after > mtime_before + 1e-6:
            print("✖ Cached file timestamp changed while origin was blocked; expected a pure cache HIT.")
            print(f"  {cached_path}: {time.ctime(mtime_before)} → {time.ctime(mtime_after)}")
            return 0

        print("✔ Served from cache with origin blocked; cached file unchanged. Awarding 20/20.")
        return 20
    finally:
        try_remove_block_rules(rules_added)

# ---------- Test 3b: TTL expire → refresh and cache timestamp updated ----------
def test_cache_refresh_after_ttl(proxy_host: str, proxy_port: int,
                                 url: str, ref_bytes: bytes, ttl_seconds: int,
                                 cache_dir: str,
                                 artifacts_dir: str) -> int:
    print_header('Test 3b — "TTL expire → origin re-fetch → cache timestamp updated" (10 pts)')

    found = find_cached_file_relaxed(cache_dir, ref_bytes, min_matches=3)
    if not found:
        print("✖ Could not locate cached file for index.html before TTL wait (relaxed search).")
        return 0
    cached_path, matched_lines = found
    print(f"(info) Using cached file: {cached_path}  (matched lines: {matched_lines})")

    try:
        mtime_before = os.path.getmtime(cached_path)
    except FileNotFoundError:
        print("✖ Cached file disappeared unexpectedly before TTL wait.")
        return 0

    wait_s = max(1, ttl_seconds) + 1
    print(f"⏳ Waiting {wait_s} seconds for cache TTL to expire...")
    time.sleep(wait_s)

    code, body, headers = fetch_via_proxy_with_headers(url, proxy_host, proxy_port, timeout=20.0)
    out_path = os.path.join(artifacts_dir, PROXY_FILE_3)
    with open(out_path, "wb") as f:
        f.write(body or b"")

    if not (code == 200 and body == ref_bytes and len(body) > 0):
        print("✖ TTL re-fetch check failed: expected 200 and body to match reference.")
        print(f"  status={code}, content_match={body == ref_bytes}")
        return 0

    try:
        mtime_after = os.path.getmtime(cached_path)
    except FileNotFoundError:
        print("✖ Cached file is missing after TTL re-fetch (unexpected).")
        return 0

    if mtime_after > mtime_before + 1e-6:
        print("✔ Cache updated after TTL; timestamp increased.")
        print(f"  {cached_path}: {time.ctime(mtime_before)} → {time.ctime(mtime_after)}")
        print("✔ Content matches reference. Awarding 10/10.")
        return 10

    print("✖ Cached file timestamp did not increase after TTL; expected refresh.")
    print(f"  {cached_path}: {time.ctime(mtime_before)} → {time.ctime(mtime_after)}")
    return 0

# ---------- Test 4: Link Prefetch (extra 10 pts) ----------
def test_link_prefetch_extra(proxy_host: str, proxy_port: int, artifacts_dir: str) -> int:
    """
    Extra credit: Link Prefetch (+10 pts total)
      - Fetch two reference assets directly (no proxy).
      - Block origin (iptables).
      - Request both assets via proxy; if served (200 + body==ref), award +5 each.
    """
    print_header('Test 4 — "Link Prefetch while origin is blocked" (extra 10 pts)')

    # 1) Fetch references directly from origin
    ref_bodies: List[bytes] = []
    for url, out in zip(PREFETCH_URLS, REF_PREFETCH_FILES):
        out_path = os.path.join(artifacts_dir, out)
        try:
            with request.urlopen(url, timeout=20.0) as resp:
                data = resp.read()
            with open(out_path, "wb") as f:
                f.write(data)
            print(f"✔ Reference fetched: {url} → {out_path} ({len(data)} bytes)")
            ref_bodies.append(data)
        except error.URLError as e:
            print(f"✖ Direct fetch failed for {url}: {e}")
            return 0

    # 2) Block origin
    parsed = urlparse(PREFETCH_URLS[0])
    origin_host = parsed.hostname or ""
    origin_ips = resolve_host_ips(origin_host, 80)
    blocked_ok, rules_added = try_add_block_rules(origin_ips)
    if not blocked_ok:
        print("✖ Failed to block origin via iptables. Cannot validate prefetch under outage.")
        return 0

    extra_points = 0
    try:
        # 3) Request via proxy while blocked
        for (url, ref_body, out_name) in zip(PREFETCH_URLS, ref_bodies, PROXY_PREFETCH_FILES):
            code, body, headers = fetch_via_proxy_with_headers(url, "127.0.0.1", proxy_port, timeout=20.0)
            out_path = os.path.join(artifacts_dir, out_name)
            with open(out_path, "wb") as f:
                f.write(body or b"")
            if code == 200 and body == ref_body and len(body) > 0:
                print(f"✔ Prefetch served from cache (blocked): {url} → +5 pts")
                extra_points += 5
            else:
                print(f"✖ Prefetch miss (or content mismatch) for {url}. status={code}, equal={body==ref_body}")
    finally:
        try_remove_block_rules(rules_added)

    print(f"(info) Link Prefetch extra points: {extra_points}/10")
    return extra_points

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Web Proxy Grading Script (Forwarding + Blocklist + Cache Tests + Prefetch Extra)")
    parser.add_argument("--port", type=int, default=8000, help="Proxy listen port (default: 8000)")
    parser.add_argument("--timeout", type=int, default=20, help="Cache TTL passed to proxy (default: 20)")
    parser.add_argument(
        "--url",
        default="http://netsys.cs.colorado.edu/index.html",
        help="URL to fetch for tests (default: netsys.cs.colorado.edu/index.html)",
    )
    parser.add_argument("--cache-dir", default="cache", help="Cache directory to clear (default: ./cache)")
    parser.add_argument("--blocklist", default=BLOCKLIST_FILENAME, help="Blocklist filename (default: blocklist)")
    parser.add_argument("--artifacts-dir", default="artifacts", help="Directory to store all artifacts (default: ./artifacts)")
    args = parser.parse_args()

    # Require root
    require_root_or_exit()

    # Artifacts directory
    ensure_dir(args.artifacts_dir)

    # Step 1: Clear cache
    clear_cache(args.cache_dir)

    # Step 2: Re-init blocklist (students typically read from CWD)
    write_blocklist(args.blocklist, BLOCKLIST_CONTENT)

    # Step 3: Build
    run_make()

    # Step 3.5: Ensure port is free (kill any process binding it)
    kill_process_using_port(args.port)

    # Step 4: Start proxy (log inside artifacts dir)
    proc = start_proxy(args.port, args.timeout, artifacts_dir=args.artifacts_dir)

    total_points = 0
    extra_points = 0
    try:
        # Test 1: Forwarding & Relaying (60)
        ref_path = os.path.join(args.artifacts_dir, REF_FILE)
        proxy_out = os.path.join(args.artifacts_dir, PROXY_FILE)
        ref_bytes = fetch_direct(args.url, ref_path)
        proxy_bytes = fetch_via_proxy(args.url, "127.0.0.1", args.port, proxy_out)
        forwarding_ok = (proxy_bytes == ref_bytes and len(proxy_bytes) > 0)
        total_points += grade_forwarding(forwarding_ok)

        # Test 2: Blocklist (10)
        pts_block, _ = test_blocklist("127.0.0.1", args.port, args.blocklist)
        total_points += pts_block

        # Test 3a: Serve from cache while origin is blocked (20)
        total_points += test_cache_hit_block_origin(
            "127.0.0.1", args.port, args.url, ref_bytes, args.cache_dir, args.artifacts_dir
        )

        # Test 3b: TTL expire → re-fetch → cache timestamp updated (10)
        total_points += test_cache_refresh_after_ttl(
            "127.0.0.1", args.port, args.url, ref_bytes, args.timeout, args.cache_dir, args.artifacts_dir
        )

        # Test 4: Link Prefetch (extra 10 pts)
        extra_points += test_link_prefetch_extra("127.0.0.1", args.port, args.artifacts_dir)

        print_header(f"TOTAL SCORE: {total_points} / 100  +  EXTRA: {extra_points} / 10  →  COMBINED: {total_points + extra_points} / 110")
        if total_points < 110:
            print("(Artifacts saved under: {})".format(os.path.abspath(args.artifacts_dir)))
            print("  - {}".format(REF_FILE))
            print("  - {}".format(PROXY_FILE))
            print("  - {}".format(PROXY_FILE_2))
            print("  - {}".format(PROXY_FILE_3))
            print("  - {}".format(PROXY_LOG))
            print("  - {}".format(", ".join(REF_PREFETCH_FILES)))
            print("  - {}".format(", ".join(PROXY_PREFETCH_FILES)))
    finally:
        stop_proxy(proc)

if __name__ == "__main__":
    main()

