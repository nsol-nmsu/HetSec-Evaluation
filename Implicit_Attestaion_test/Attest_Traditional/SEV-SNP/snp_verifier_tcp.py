#!/usr/bin/env python3
import json, os, socket, struct, subprocess, tempfile
from typing import Optional

def recvn(sock, n: int) -> bytes:
    b = b""
    while len(b) < n:
        x = sock.recv(n - len(b))
        if not x:
            raise ConnectionError("socket closed")
        b += x
    return b

def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout

def verify_snp_report_with_snpguest(
    report_bytes: bytes,
    expected_measurement_hex: Optional[str],
    expected_report_data_hex: Optional[str],
    endorser: str = "vcek",   # or "vlek"
) -> dict:
    """
    Uses snpguest workflow:
      fetch ca  (ARK/ASK or ARK/ASVK)
      fetch vcek (or vlek flow if your environment supports it)
      verify certs
      verify attestation (+ optional measurement/report-data checks)
    """
    expected_measurement_hex = expected_measurement_hex
    #expected_report_data_hex = "0x" + expected_report_data_hex


    with tempfile.TemporaryDirectory(prefix="snpverify-") as td:
        report_path = os.path.join(td, "report.bin")
        certs_dir = os.path.join(td, "certs")
        os.mkdir(certs_dir)

        with open(report_path, "wb") as f:
            f.write(report_bytes)

        out_lines = []

        # 1) Fetch CA chain based on report processor-model
        # snpguest fetch ca pem ./certs -r report.bin -e vcek|vlek
        rc, out = run(["snpguest", "fetch", "ca", "pem", certs_dir, "-r", report_path, "-e", endorser])
        out_lines.append(out)
        if rc != 0:
            return {"ok": False, "stage": "fetch_ca", "rc": rc, "out": "".join(out_lines)}

        # 2) Fetch VCEK corresponding to chip_id + reported_tcb from report
        # snpguest fetch vcek pem ./certs report.bin
        if endorser == "vcek":
            rc, out = run(["snpguest", "fetch", "vcek", "pem", certs_dir, report_path])
            out_lines.append(out)
            if rc != 0:
                return {"ok": False, "stage": "fetch_vcek", "rc": rc, "out": "".join(out_lines)}

        # 3) Verify cert chain
        rc, out = run(["snpguest", "verify", "certs", certs_dir])
        out_lines.append(out)
        if rc != 0:
            return {"ok": False, "stage": "verify_certs", "rc": rc, "out": "".join(out_lines)}

        # 4) Verify attestation report (+ policy checks)
        cmd = ["snpguest", "verify", "attestation", certs_dir, report_path]
        if expected_measurement_hex:
            cmd = ["snpguest", "verify", "attestation", "--measurement", expected_measurement_hex, certs_dir, report_path]
        if expected_report_data_hex:
            # If you include both, snpguest needs both flags in one command.
            # Rebuild command to include both flags.
            base = ["snpguest", "verify", "attestation"]
            if expected_measurement_hex:
                base += ["--measurement", expected_measurement_hex]
            base += ["--report-data", expected_report_data_hex, certs_dir, report_path]
            cmd = base

        rc, out = run(cmd)

        out_lines.append(out)
        if rc != 0:
            return {"ok": False, "stage": "verify_attestation", "rc": rc, "out": "".join(out_lines)}

        return {"ok": True, "stage": "ok", "rc": 0, "out": "".join(out_lines)}

def handle_conn(c: socket.socket):
    jlen = struct.unpack("!I", recvn(c, 4))[0]
    j = json.loads(recvn(c, jlen).decode("utf-8")) if jlen else {}
    rlen = struct.unpack("!I", recvn(c, 4))[0]
    report = recvn(c, rlen)

    measurement = j.get("measurement")
    report_data = j.get("report_data")
    endorser = j.get("endorser", "vcek")

    result = verify_snp_report_with_snpguest(report, measurement, report_data, endorser=endorser)

    payload = json.dumps(result).encode("utf-8")
    wire_rc = 0 if result.get("ok") else 1

    c.sendall(struct.pack("!I", wire_rc) + struct.pack("!I", len(payload)) + payload)



def main():
    host, port = "0.0.0.0", 7777
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(64)
    print(f"SNP verifier listening on {host}:{port}")
    while True:
        c, _ = s.accept()
        try:
            handle_conn(c)
        except Exception as e:
            payload = json.dumps({"ok": False, "stage": "server_exception", "err": str(e)}).encode("utf-8")
            try:
                c.sendall(struct.pack("!I", 1) + struct.pack("!I", len(payload)) + payload)
            except Exception:
                pass
        finally:
            c.close()

if __name__ == "__main__":
    main()
