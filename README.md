# le0 - IRC Bot

A Python IRC bot with weather, network lookups, CVE search, YouTube link cards, utilities, fun commands, and text tools. ASCII-styled output with IRC color formatting.

## Features

### Weather
- Current weather with temperature, humidity, wind, pressure, visibility, sunrise/sunset
- 3-day forecast with highs, lows, and precipitation data

### Info
- Urban Dictionary lookups
- Current time (UTC)
- HTTP status code reference

### Network & Lookups
- Page title fetcher for any URL
- **YouTube link cards** -- any YouTube link pasted in-channel auto-expands to a one-line card with title, channel, views, likes, and length (also via `%title`)
- Dictionary definitions and translation
- URL shortener and stock quotes
- Site up/down check, DNS lookup, GeoIP, and `whois`

### Security
- **CVE search** -- `%vuln <text>` searches the NVD by keyword or exact CVE-ID and returns the most recent matches with CVSS score, severity, affected product, and a one-line summary

### Gitea activity
- **Gitea webhook** -- the bot opens an HTTP listener that a Gitea instance posts to; new pushes, issues, pull requests, releases, and tag/branch creations are announced as one-line cards in the configured channels (HMAC-SHA256 signature verified; toggle with `GITEA_WEBHOOK_ENABLED` in config)

### Fun
- Coin flip with ASCII art
- Dice rolling (any XdY format)
- Magic 8-ball with ASCII art
- Rock Paper Scissors
- Random fun facts

### Social
- Quote database -- save and retrieve quotes from chat
- `%tell` -- leave a message for a user, delivered when they're next active

### Utility
- Seen tracker -- check when someone was last active
- Ping / uptime

### Tools
- Safe math calculator
- MD5 / SHA1 / SHA256 hashing
- Base64 encode and decode
- Text reversal
- Mocking case (SpOnGeBoB)

### Admin
- **Clone guard** -- auto kick-bans bots that copy le0's output: verbatim echoes of recent bot lines, or rival YouTube cards posted off the same pasted link (needs ops; toggle with `CLONE_GUARD` in config). There is only room for one bot.
- Hostmask-based authentication (`nick!user@host` with wildcard support)
- Admin commands bypass rate limiting
- `%join`, `%part`, `%quit`, `%say`, `%nick`, `%kick`, `%raw`
- Admin section only visible in `%help` to authenticated admins

### Security & Safety
- Input sanitization on all commands (CRLF injection, IRC control chars, length limits)
- URL parameter encoding on all API calls
- Per-user rate limiting (2s cooldown)
- Nickname validation against IRC spec
- Safe eval with no builtins for calculator
- Exponent cap to prevent resource exhaustion

### Technical
- SSL/TLS support with TLS 1.2 minimum, optional certificate verification bypass
- SASL PLAIN and NickServ authentication
- Multi-network support via separate config files
- Temperature-based color coding
- ASCII-styled output (no emoji dependencies)
- Anti-flood protection between multi-line messages
- Configurable command prefix

## Installation

Python 3.7+

```bash
pip install -r requirements.txt
```

## Configuration

Settings live in `config.py` (default) or any alternate config file passed as a CLI argument.

```python
# Connection
SERVER = "irc.example.net"
PORT = 6697                     # 6697 for SSL, 6667 for non-SSL
NICKNAME = "le0"
CHANNELS = ["#channel"]
COMMAND_PREFIX = "%"

# Admin hostmasks (nick!user@host format, wildcards supported)
# Examples: "*!*@*.myisp.net"  "mynick!*@*"
ADMINS = ["*!*@*.example.net"]

# SSL / Auth
USE_SSL = True
VERIFY_SSL = True               # False to allow self-signed/unverified certs
PASSWORD = None                 # Server password (if needed)
NICKSERV_PASS = None            # NickServ identify password (if needed)
SASL_USERNAME = None            # SASL plain username (if needed)
SASL_PASSWORD = None            # SASL plain password (if needed)
```

### API keys (optional, set via environment variables)

API keys are read from the environment, not stored in the config file:

```bash
# NVD (CVE search) -- without a key: 5 req/30s; with a key: 50 req/30s
export NVD_API_KEY="your-nvd-key"

# YouTube Data API v3 -- enables full link cards (views, likes, length).
# Without a key, links fall back to title + channel only via oEmbed.
export YOUTUBE_API_KEY="your-youtube-key"
```

Get a YouTube key from the [Google Cloud Console](https://console.cloud.google.com/): create a project, enable **YouTube Data API v3**, then create an API key under **Credentials**.

### Gitea webhook

The bot can announce activity from a Gitea instance by receiving webhook events. Set these in `config.py`:

```python
GITEA_WEBHOOK_ENABLED = True
GITEA_WEBHOOK_HOST = "0.0.0.0"       # Listen address
GITEA_WEBHOOK_PORT = 8089            # Must match the port in the Gitea webhook URL
GITEA_WEBHOOK_SECRET = "shared-secret"  # Same value you set in Gitea; verifies X-Gitea-Signature
GITEA_WEBHOOK_CHANNELS = ["#dev"]    # Channels to announce in (empty = all CHANNELS)
GITEA_URL = "https://git.interdo.me" # Instance base URL (display only)
```

Then in Gitea, under **Repository (or Organization) Settings → Webhooks → Add Webhook → Gitea**:

- **Target URL:** `http://<bot-host>:8089/`
- **HTTP Method:** `POST`
- **Content Type:** `application/json`
- **Secret:** the same value as `GITEA_WEBHOOK_SECRET`
- **Trigger On:** choose the events you want (pushes, issues, pull requests, releases, branch/tag creation), or "All Events"

Handled events: `push`, `issues` (opened/closed/reopened), `pull_request` (opened/closed/merged/reopened), `release` (published/updated), and `create` (tag/branch). Other events are ignored.

> **Note:** the listener binds an inbound TCP port. Make sure your firewall allows Gitea to reach it, and always set a non-empty `GITEA_WEBHOOK_SECRET` outside of local testing — an empty secret accepts unsigned requests. `GET /` returns a plain health check for connectivity testing.

Example output:

```
 git  Gitea | dom/le0 | dom pushed 3 commits to main | abcdef1 Fix the webhook listener (+2 more) | https://git.interdo.me/dom/le0/compare/a...b
 git  Gitea | dom/le0 | alice opened issue #12 | Crash on startup | https://git.interdo.me/dom/le0/issues/12
 git  Gitea | dom/le0 | bob merged PR #5 | Add gitea webhook | https://git.interdo.me/dom/le0/pulls/5
```

## Usage

```bash
# Default (uses config.py)
python3 le0.py

# Alternate config (e.g. config.efnet.py)
python3 le0.py config.efnet
```

Multiple config files can coexist for different networks (e.g. `config.efnet.py`, `config.libera.py`).

## Commands

```
WEATHER
  %weather <location>  or  %w <location>      Current weather
  %forecast <location> or  %f <location>      3-day forecast

INFO
  %urban <term>        or  %ud <term>         Urban Dictionary lookup
  %time [location]                            Current time (UTC)
  %http <code>         or  %h <code>          HTTP status code reference

NETWORK & LOOKUPS
  %title <url>         or  %t <url>           Page title (YouTube card for YT links)
  %define <word>       or  %def <word>        Dictionary definition
  %tr <lang> <text>    or  %translate ...     Translate text
  %shorten <url>       or  %short <url>        Shorten a URL
  %stock <ticker>      or  %stocks <ticker>   Stock quote
  %isup <host>         or  %up <host>         Check if a site is up
  %dns <hostname>      or  %nslookup <host>   DNS lookup
  %geo <ip|host>       or  %geoip / %ip       GeoIP lookup
  %whois <nick>                               WHOIS a user
  (pasting any YouTube link auto-posts a card: title, channel, views, likes, length)

SECURITY
  %vuln <search text>                         Search NVD for CVEs (keyword or CVE-ID)

FUN
  %coin  or  %flip                            Flip a coin
  %roll [XdY]  or  %dice [XdY]                Roll dice (default: 1d6)
  %8ball <question>  or  %8 <question>        Magic 8-ball
  %rps <rock|paper|scissors>                  Rock Paper Scissors
  %fact                                       Random fun fact

SOCIAL
  %quote                                      Random quote from database
  %addquote <text>                            Add a quote
  %tell <nick> <message>  or  %remind ...     Leave a message for a user

UTILITY
  %seen <nick>                                When was a user last active
  %ping                                       Pong
  %uptime                                     Bot uptime

TOOLS
  %calc <expression>                          Math calculator
  %hash <text>                                MD5/SHA1/SHA256 hashes
  %base64 <encode|decode> <text>  or  %b64    Base64 encode/decode
  %reverse <text>                             Reverse text
  %mock <text>                                SpOnGeBoB mOcKiNg CaSe

ADMIN  (hostmask-authenticated only)
  %join <channel>                             Join a channel
  %part [channel]                             Leave a channel (defaults to current)
  %quit [message]                             Disconnect the bot
  %say <channel> <message>                    Speak in any channel
  %nick <newnick>                             Change the bot's nick
  %kick <nick> [reason]                       Kick a user from the current channel
  %raw <command>                              Send a raw IRC command

HELP
  %help                                       Show all commands in IRC
```

## Example Output

```
<user> %weather London
<le0> ----------- Weather | London, United Kingdom -----------
<le0>  > Condition: Partly cloudy  Temp: 12°C / 54°F  Feels: 10°C / 50°F
<le0>  > Humidity: 76%  Wind: 15km/h W  Clouds: 65%
<le0>  > Pressure: 1013hPa  Visibility: 10km  Sunrise: 07:45  Sunset: 16:30

<user> https://youtu.be/dQw4w9WgXcQ
<le0> ▶ YouTube  Rick Astley - Never Gonna Give You Up | Channel: Rick Astley | Views: 1,787,480,087 | Likes: 19,203,655 | Length: 3:34

<user> %vuln jellyfin
<le0> ----------- CVE Search | jellyfin | 32 matches -----------
<le0>  > CVE-2026-49247 [8.8] 2026-06-24 Jellyfin —
<le0>  >   An authenticated user can ...
<le0>  >   URL: https://nvd.nist.gov/vuln/detail/CVE-2026-49247

<user> %roll 2d6
<le0> ----------- Dice Roll -----------
<le0>  > 2d6 > [4, 5] = 9
```

Actual output includes IRC color codes for a much prettier display.
