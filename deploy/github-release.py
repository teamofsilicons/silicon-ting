#!/usr/bin/env python3
"""Deploy a tested public GitHub backend archive to the production host over SSM."""
import argparse
import json
import pathlib
import re
import shlex
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("commit", help="Full commit SHA from the successful backend workflow")
parser.add_argument("--region", default="us-east-1")
args = parser.parse_args()
if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
    parser.error("commit must be a full lowercase Git SHA")


def aws(*parts):
    return json.loads(subprocess.check_output(["aws", "--region", args.region, *parts], text=True))


def get(url):
    return subprocess.check_output(["curl", "-fsSL", "--retry", "3", "--max-time", "60", url], text=True)


tag = "server-" + args.commit
base = "https://github.com/teamofsilicons/silicon-ting/releases/download/" + tag
filename = "ting-server-" + args.commit + ".tar.gz"
entries = [line.split() for line in get(base + "/SHA256SUMS").splitlines() if line.strip()]
matches = [digest for digest, name in entries if name == filename and re.fullmatch(r"[0-9a-f]{64}", digest)]
if len(entries) != 1 or len(matches) != 1:
    raise SystemExit("Release checksum manifest must contain exactly the expected archive")
checksum = matches[0]
stack = aws("cloudformation", "describe-stacks", "--stack-name", "silicon-ting-production")["Stacks"][0]
outputs = {item["OutputKey"]: item["OutputValue"] for item in stack["Outputs"]}
release = args.commit[:16] + "-" + checksum[:12]
remote = "/opt/ting/releases/" + release
command = "\n".join([
    "set -eu",
    "umask 022",
    "mkdir -p " + remote,
    "curl -fsSL --retry 3 --connect-timeout 10 --max-time 180 " + shlex.quote(base + "/" + filename) + " -o " + remote + ".tgz",
    "printf '%s\\n' " + shlex.quote(checksum + "  " + remote + ".tgz") + " | sha256sum -c -",
    "tar -xzf " + remote + ".tgz -C " + remote,
    'test "$(cat ' + remote + '/BUILD_COMMIT)" = ' + shlex.quote(args.commit),
    "chmod 755 " + remote + "/ting-server " + remote + "/caddy",
    "bash " + remote + "/install.sh " + remote + " " + shlex.quote(args.region),
])
with tempfile.TemporaryDirectory() as directory:
    request = pathlib.Path(directory) / "command.json"
    request.write_text(json.dumps({
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [outputs["InstanceId"]],
        "Parameters": {"commands": [command], "executionTimeout": ["600"]},
        "Comment": "Ting verified GitHub backend " + args.commit[:16],
    }))
    command_id = aws("ssm", "send-command", "--cli-input-json", "file://" + str(request))["Command"]["CommandId"]
print(json.dumps({"release": release, "commit": args.commit, "checksum": checksum, "instance": outputs["InstanceId"], "command_id": command_id}), flush=True)
for _ in range(150):
    time.sleep(2)
    result = aws("ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", outputs["InstanceId"])
    if result["Status"] in ("Pending", "InProgress", "Delayed"):
        continue
    print(result["Status"], result["StandardOutputContent"], result["StandardErrorContent"])
    raise SystemExit(0 if result["Status"] == "Success" else 1)
raise SystemExit("Still running; inspect command_id before retrying.")
