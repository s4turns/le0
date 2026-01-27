# le0 - IRC Bot

A feature-rich Python IRC bot with weather, utilities, and fun commands. Now with colorful output!

## Features

### Weather Commands
- **Current Weather**: Get real-time weather with colorful temperature displays
- **Weather Forecast**: Get multi-day weather forecasts with color-coded temperatures

### Info Commands
- **Urban Dictionary**: Look up slang and terms
- **Time**: Get current time for any location

### Fun Commands
- **Coin Flip**: Flip a coin
- **Dice Roll**: Roll dice (supports any XdY format like 2d6, 1d20)
- **Magic 8-Ball**: Ask the magic 8-ball a question

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

Edit the bot configuration at the bottom of `le0.py`:

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

### Common IRC Servers

- **Libera.Chat**: `irc.libera.chat:6697` (SSL)
- **OFTC**: `irc.oftc.net:6697` (SSL)
- **EFNet**: `irc.efnet.org:6697` (SSL)
- **Undernet**: `irc.undernet.org:6667` (non-SSL)

## Usage

### Running the Bot

```bash
python3 le0.py
```

### Available Commands

Once the bot is running in your IRC channel, users can use these commands:

#### Weather Commands
```
%weather <location> or %w <location>     - Get current weather
%forecast <location> [days] or %f        - Get weather forecast (up to 3 days)
```

Examples:
- `%weather London`
- `%w New York`
- `%forecast Tokyo 2`

#### Info Commands
```
%urban <term> or %ud <term>              - Look up Urban Dictionary definition
%time [location]                         - Get current time (optionally for a location)
```

Examples:
- `%urban yeet`
- `%time` (shows UTC time)
- `%time Tokyo`

#### Fun Commands
```
%coin or %flip                          - Flip a coin
%roll [XdY] or %dice [XdY]              - Roll dice (default: 1d6)
%8ball <question> or %8 <question>      - Ask the magic 8-ball
```

Examples:
- `%coin`
- `%roll 2d20`
- `%dice 1d100`
- `%8ball Will I win the lottery?`

#### Utility Commands
```
%seen <nick>                             - Check when someone was last active
%help                                    - Show all commands
```

Examples:
- `%seen bob`
- `%help`

**Note:** The command prefix is configurable. By default it's `%`, but you can change it to `!`, `.`, or any character(s) you prefer in the configuration.

## Example Output

```
<user> %weather London
<le0> London → Partly cloudy | 🌡️ 12°C (54°F) | Feels: 10°C (50°F) | 💧 76% | 💨 15km/h W

<user> %forecast Tokyo 2
<le0> Forecast for Tokyo
<le0> 2025-01-27 → Clear | High: 15°C (59°F) | Low: 8°C (46°F)
<le0> 2025-01-28 → Sunny | High: 16°C (61°F) | Low: 9°C (48°F)

<user> %urban yeet
<le0> yeet → To throw something with a lot of force

<user> %roll 2d6
<le0> 🎲 2d6 → [4, 5] = 9

<user> %8ball Will it rain tomorrow?
<le0> 🎱 Outlook good

<user> %coin
<le0> 🪙 Heads

<user> %seen bob
<le0> bob was last seen 5 minutes ago in #test saying: hey everyone!
```

Note: Actual output includes IRC color codes for a much prettier display!

## Customization

### Adding More Commands

You can easily add more commands by extending the `handle_command` method:

```python
def handle_command(self, channel: str, nick: str, message: str):
    parts = message.strip().split()
    command = parts[0].lower()
    
    if command == f"{self.command_prefix}mycommand":
        # Your command logic here
        response = IRCColors.color("Response message", IRCColors.CYAN)
        self.send_message(channel, response)
```

### Using IRC Colors

The bot includes an `IRCColors` class with various colors and formatting options:

```python
# Colors
IRCColors.RED, IRCColors.BLUE, IRCColors.GREEN, IRCColors.CYAN, etc.

# Formatting
IRCColors.BOLD, IRCColors.ITALIC, IRCColors.UNDERLINE

# Helper methods
IRCColors.color(text, fg_color)
IRCColors.bold(text)
IRCColors.temp_color(temp_celsius)  # Returns color based on temperature
```

### Using Different Weather APIs

The bot currently uses wttr.in (no API key needed). You can modify the `get_weather` method to use other APIs:

- **OpenWeatherMap**: Free tier available, requires API key
- **WeatherAPI**: Free tier available, requires API key
- **Weather.gov**: US only, no API key needed

## Troubleshooting

### Connection Issues
- Make sure you're using the correct port (6697 for SSL, 6667 for non-SSL)
- Some networks require registration - check the network's documentation
- Try disabling SSL if connection fails: `use_ssl=False` and use port 6667

### Rate Limiting
- The bot includes a small delay between forecast messages to avoid flooding
- If you get kicked for excess flood, increase the delay in the forecast command

### Nickname Already in Use
- Change the `nickname` in the configuration
- Some networks allow you to register nicknames - check the network's documentation

## License

Free to use and modify as needed.

## Contributing

Feel free to add more features:
- More weather data (UV index, sunrise/sunset, weather alerts)
- Web scraping commands (news headlines, reddit posts, etc.)
- Database for storing user stats or preferences  
- Admin commands for bot management (kick, ban, etc.)
- Quote database (save and retrieve quotes)
- RSS feed monitoring
- Currency conversion
- URL title fetching
- Custom command aliases per channel
