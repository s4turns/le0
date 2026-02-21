# le0 - IRC Bot

A Python IRC bot with weather, utilities, fun commands, and text tools. ASCII-styled output with IRC color formatting.

## Features

### Weather
- Current weather with temperature, humidity, wind, pressure, visibility, sunrise/sunset
- 3-day forecast with highs, lows, and precipitation data

### Info
- Urban Dictionary lookups
- Current time (UTC)

### Fun
- Coin flip with ASCII art
- Dice rolling (any XdY format)
- Magic 8-ball with ASCII art
- Rock Paper Scissors
- Random fun facts

### Social
- Quote database -- save and retrieve quotes from chat

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
- Hostmask-based authentication (`nick!user@host` with wildcard support)
- Admin commands bypass rate limiting
- `%join`, `%part`, `%quit`, `%say`, `%nick`, `%kick`, `%raw`
- Admin section only visible in `%help` to authenticated admins

### Security
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

FUN
  %coin  or  %flip                            Flip a coin
  %roll [XdY]  or  %dice [XdY]               Roll dice (default: 1d6)
  %8ball <question>  or  %8 <question>        Magic 8-ball
  %rps <rock|paper|scissors>                  Rock Paper Scissors
  %fact                                       Random fun fact

SOCIAL
  %quote                                      Random quote from database
  %addquote <text>                            Add a quote

UTILITY
  %seen <nick>                                When was a user last active
  %ping                                       Pong
  %uptime                                     Bot uptime

TOOLS
  %calc <expression>                          Math calculator
  %hash <text>                                MD5/SHA1/SHA256 hashes
  %base64 <encode|decode> <text>              Base64 encode/decode
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

<user> %roll 2d6
<le0> ----------- Dice Roll -----------
<le0>  > 2d6 > [4, 5] = 9

<user> %calc 2^10
<le0> ----------- Calculator -----------
<le0>  > 2**10 = 1024

<user> %rps rock
<le0> ----------- Rock Paper Scissors -----------
<le0>  > You: ROCK vs Bot: SCISSORS
<le0>  > Result: YOU WIN
```

Actual output includes IRC color codes for a much prettier display.
