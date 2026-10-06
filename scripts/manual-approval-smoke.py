"""Exercise the example's wait/approve/continue flow against a local test server."""
import argparse
import json
import queue
import subprocess
import threading
import urllib.request
from pathlib import Path


def run(client_path, relay, admin, token_file):
    token = Path(token_file).read_text().strip()
    client = subprocess.Popen([client_path, "--relay", relay, "--request-access"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()

    def read_lines():
        for line in client.stdout:
            lines.put(line)
        lines.put(None)

    thread = threading.Thread(target=read_lines, daemon=True)
    thread.start()
    seen = []
    try:
        ids = []
        while len(ids) < 2:
            line = lines.get(timeout=15)
            if line is None:
                raise RuntimeError("client stopped before printing both IDs")
            seen.append(line)
            if line.startswith(("endpoint A: ", "endpoint B: ")):
                ids.append(line.split(": ", 1)[1].strip())
        while not any("Press Enter to connect." in line for line in seen):
            line = lines.get(timeout=15)
            if line is None:
                raise RuntimeError("client stopped before requesting approval")
            seen.append(line)
        if sum("connection refused;" in line for line in seen) != 2:
            raise RuntimeError("both unknown endpoints must be denied before approval")
        request = urllib.request.Request(
            f"{admin}/admin/pending",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(request, timeout=5) as response:
            pending = json.load(response)
        if pending["mode"] != "requests" or not set(ids).issubset(
                {entry["endpoint_id"] for entry in pending["requests"]}):
            raise RuntimeError("denied endpoints did not appear in access requests")
        if client.poll() is not None:
            raise RuntimeError("manual client did not wait for approval")
        for endpoint in ids:
            request = urllib.request.Request(
                f"{admin}/admin/endpoints/{endpoint}", method="PUT",
                data=json.dumps(dict(label="manual smoke", approved=True)).encode(),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status != 200:
                    raise RuntimeError(f"approval failed: {response.status}")
        client.stdin.write("\n")
        client.stdin.flush()
        client.wait(timeout=15)
        thread.join(timeout=2)
        while not lines.empty():
            line = lines.get_nowait()
            if line is not None:
                seen.append(line)
        if client.returncode != 0 or "relayed transfer OK\n" not in seen:
            raise RuntimeError("manual transfer failed: " + client.stderr.read())
        print("manual approval smoke: OK")
    finally:
        if client.poll() is None:
            client.kill()
            client.wait(timeout=5)
        for stream in (client.stdin, client.stdout, client.stderr):
            stream.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client")
    parser.add_argument("--relay", required=True)
    parser.add_argument("--admin", required=True)
    parser.add_argument("--token-file", required=True)
    args = parser.parse_args()
    run(args.client, args.relay, args.admin, args.token_file)
