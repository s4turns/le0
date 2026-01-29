# le0 - IRC Bot

<img width="2914" height="1453" alt="image" src="https://github.com/user-attachments/assets/e39f2c7d-bb93-4d83-8c91-4570c6e88a0f" />

A Python IRC bot with weather, utilities, and fun commands with colorful output!

## Features

### Weather Commands
- **Current Weather**: Get real-time weather with colorful temperature displays
- **Weather Forecast**: 3-day forecasts with precipitation data (no UV index)

### Info Commands
- **Urban Dictionary**: Look up slang and terms
- **Time**: Get current time for any location

### Fun Commands
- **Coin Flip**: Flip a coin
- **Dice Roll**: Roll dice (supports any XdY format)
- **Magic 8-Ball**: Ask the magic 8-ball a question

### Social Features
- **Quote Database**: Save and retrieve random quotes from chat

### Utility Commands
- **Seen Tracker**: Check when someone was last active
- **Help**: Show all available commands

### Technical Features
- IRC color formatting for beautiful output
- SSL/TLS support for secure connections
- Temperature-based color coding (hot = red, cold = blue)
- Easy to configure for any IRC network
- Anti-flood protection

## Installation

1. Install Python 3.7 or higher

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Edit the bot configuration at the bottom of `irc_bot.py`:

```python
bot = IRCBot(
    server="irc.blcknd.network",       # IRC server address
    port=6697,                          # Port (6697 for SSL, 6667 for non-SSL)
    nickname="le0",                     # Your bot's nickname
    channels=["#test"],                 # List of channels to join
    use_ssl=True,                       # Use SSL/TLS
    password=None,                      # Server password (optional)
    command_prefix="%"                  # Command trigger (default: "%", can use "!", ".", etc.)
)
```

## Usage

### Running the Bot

```bash
python3 irc_bot.py
```

### Available Commands

#### Weather Commands
```
%weather <location> or %w <location>     - Get current weather
%forecast <location> or %f <location>    - Get 3-day weather forecast
```

#### Info Commands
```
%urban <term> or %ud <term>              - Urban Dictionary lookup
%time [location]                         - Get current time
```

#### Fun Commands
```
%coin or %flip                           - Flip a coin
%roll [XdY] or %dice [XdY]              - Roll dice (default: 1d6)
%8ball <question> or %8 <question>      - Ask the magic 8-ball
```

#### Social Commands
```
%quote                                   - Get a random quote from database
%addquote <text>                         - Add a quote to database
```

#### Utility Commands
```
%seen <nick>                             - Check when someone was last active
%help                                    - Show all commands
```

## Example Output

```
<user> %weather London
<le0> London, United Kingdom → Partly cloudy | 🌡️ 12°C (54°F) | Feels: 10°C (50°F)
<le0> 💧 76% | 💨 15km/h W | ☁️ 65%
<le0> 📊 1013hPa | 👁️ 10km | 🌅 07:45 | 🌇 16:30

<user> %roll 2d6
<le0> 🎲 2d6 → [4, 5] = 9

<user> %8ball Will it rain tomorrow?
<le0> 🎱 Outlook good

<user> %addquote "This bot is awesome!"
<le0> ✓ Quote #1 added

<user> %quote
<le0> 💬 Quote #1: This bot is awesome!
```

Note: Actual output includes IRC color codes for a much prettier display!
