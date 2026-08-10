# XSS - Reflected - URI (Root-Me)

- **Category**: Web
- **Difficulty**: Medium
- **Points**: 450
- **Est. time**: ~1h
- **Tagline**: "Mirror mirror..."
- **Description**: Site presents the video game "The Pirate Creek". Recently updated, but a vulnerability still seems to exist. Get the administrator's account to steal his treasure!
- **Flag format**: `RM{...}`

## Goal
Steal the admin's session/account via a reflected XSS delivered through the URI.
Almost certainly: craft payload → exfil `document.cookie` to a listener → admin bot visits URL → get admin cookie → log in as admin → read flag.

## Status
- [ ] Target instance URL obtained
- [ ] Fingerprint app / find reflection point
- [ ] Identify filter + bypass
- [ ] Exfil endpoint set up
- [ ] Admin cookie captured
- [ ] Flag

## Log
