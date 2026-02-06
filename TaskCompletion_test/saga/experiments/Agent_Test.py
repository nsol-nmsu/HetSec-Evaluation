import base64, json
from pathlib import Path

def inspect(agent_json_path: str):
    m = json.loads(Path(agent_json_path).read_text())
    cert_bytes = base64.b64decode(m["agent_cert"])
    pac_bytes = base64.b64decode(m["pac"])
    sig_bytes = base64.b64decode(m["agent_sig"])

    cert_kind = "PEM" if cert_bytes.startswith(b"-----BEGIN") else "DER/OTHER"
    print(agent_json_path)
    print("  IP:", m.get("IP"))
    print("  cert encoding:", cert_kind, "len:", len(cert_bytes))
    print("  pac len:", len(pac_bytes), "sig len:", len(sig_bytes))

inspect("../saga/user/bob@mail.com:calendar_agent/agent.json")
inspect("../saga/user/bob@mail.com:writing_agent/agent.json")