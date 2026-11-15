"""Local bootstrap ownership checks; generated state lives only in dist/."""
import hashlib
import json
import os
import pathlib
import sys

operation, repo_arg, profile, *identity = sys.argv[1:]
repo = pathlib.Path(repo_arg).resolve()
state_file = repo / "dist/native-amd64/owner.json"
config_root = os.environ.get("COLIMA_HOME")
if not config_root:
    legacy = pathlib.Path.home() / ".colima"
    xdg = pathlib.Path(os.environ.get("XDG_CONFIG_HOME", pathlib.Path.home() / ".config"))
    config_root = legacy if legacy.exists() else xdg / "colima"
config = pathlib.Path(config_root) / profile / "colima.yaml"
if operation == "profile-endpoint":
    print(f"unix://{config.parent / 'docker.sock'}")
    sys.exit(0)

try:
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    if state and (state.get("repository") != str(repo) or state.get("profile") != profile):
        raise ValueError("bootstrap ownership belongs to another repository/profile")
    digest = hashlib.sha256(config.read_bytes()).hexdigest()
    if operation == "profile-check":
        if not state or state.get("profile_config_sha256") != digest:
            raise ValueError("profile is unowned or its configuration changed; inspect it before reuse")
    elif operation == "profile-record":
        state.update(repository=str(repo), profile=profile, profile_config_sha256=digest)
        state_file.write_text(json.dumps(state, sort_keys=True) + "\n")
    elif operation == "guest-check-or-record":
        if not state or state.get("profile_config_sha256") != digest:
            raise ValueError("profile ownership must be verified first")
        machine_id, docker_id = identity
        if not machine_id or not docker_id:
            raise ValueError("guest identity is missing")
        expected = {"machine_id": machine_id, "docker_id": docker_id}
        if "guest" in state and state["guest"] != expected:
            raise ValueError("guest machine or Docker identity changed; refusing context reuse")
        if "guest" not in state:
            state["guest"] = expected
            state_file.write_text(json.dumps(state, sort_keys=True) + "\n")
    else:
        raise ValueError("unsupported ownership operation")
except (OSError, ValueError, KeyError) as exc:
    sys.exit(f"Dedicated VM ownership check failed: {exc}")
