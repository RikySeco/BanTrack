# BanTrack
A Fail2ban companion that turns raw ban events into structured, queryable, geolocated security data.

## 01 / the problem
### Bans happen, then vanish
Fail2ban does one job well: it bans IP addresses that misbehave. But once an IP is banned, the event is gone — buried in log files, with no history, no context, no way to ask *who has been attacking me, from where, and what were they trying to do*?
I wanted visibility, not just protection: a permanent, structured record of every ban, and a way to see the bigger picture behind the individual events.

## 02 / what it does
### Every ban, recorded and enriched
BanTrack hooks into Fail2ban and logs every ban and unban event to a database. For each event it records the offending IP, the jail that triggered it, the number of failures, the ban duration — and the actual log lines the attacker generated before being banned, so I can see **what** they were attempting.
Each IP is then enriched with geolocation data — country, region, coordinates — via the `ip-api.com` service, turning a bare list of addresses into something you can actually map and analyze.

## 03 / how it works
### Straight from Fail2ban to the database
BanTrack runs as a native Fail2ban action written in Python (`ActionPython`) rather than a shell script. When Fail2ban bans an IP, it calls the action directly and hands over the event data as a Python dictionary — no shell, no escaping issues in between.
The action writes the enriched event to a MySQL database. If **MySQL** is unreachable, it transparently falls back to a local **SQLite** database, so no event is ever lost even when the main database is temporarily down.

## 04 / tech & key decisions
### The choices behind it
#### ActionPython instead of a shell script
My first version passed event data as shell arguments. It worked for simple fields, but the `matches` field — the attacker's own log lines — contains special characters that break shell escaping, and the data got corrupted. Moving to ActionPython removed the shell from the equation entirely: Fail2ban hands the data straight to Python, intact.
#### SQLite as the fallback store
It's lightweight and file-based, with no separate service to keep running. Since it only gets written to when MySQL is down, it's the right tool for a safety net that should stay out of the way.
#### MySQL as the primary store
I already knew it well, which kept the learning curve low and let me focus on the logic of the tool rather than on the database itself.

## 05 / roadmap
### What's next
BanTrack is open source (GPLv3) and still evolving. The next milestone is a self-hosted dashboard to visualize bans over time and plot attacker origins on a map — turning the data BanTrack already collects into an at-a-glance security overview.
