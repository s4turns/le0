#!/usr/bin/env python3
"""
le0 - IRC Bot
"""

import socket
import ssl
import time
import re
import random
import hashlib
import base64
import urllib.parse
import requests
from typing import Optional


class IRCColors:
    """IRC color and formatting codes."""
    # Colors
    WHITE = "\x0300"
    BLACK = "\x0301"
    BLUE = "\x0302"
    GREEN = "\x0303"
    RED = "\x0304"
    BROWN = "\x0305"
    PURPLE = "\x0306"
    ORANGE = "\x0307"
    YELLOW = "\x0308"
    LIGHT_GREEN = "\x0309"
    CYAN = "\x0310"
    LIGHT_CYAN = "\x0311"
    LIGHT_BLUE = "\x0312"
    PINK = "\x0313"
    GREY = "\x0314"
    LIGHT_GREY = "\x0315"

    # Formatting
    BOLD = "\x02"
    ITALIC = "\x1D"
    UNDERLINE = "\x1F"
    RESET = "\x0F"

    @staticmethod
    def color(text: str, fg: str, bg: str = None) -> str:
        """Apply color to text."""
        if bg:
            return f"{fg},{bg}{text}{IRCColors.RESET}"
        return f"{fg}{text}{IRCColors.RESET}"

    @staticmethod
    def bold(text: str) -> str:
        """Make text bold."""
        return f"{IRCColors.BOLD}{text}{IRCColors.RESET}"

    @staticmethod
    def temp_color(temp_c: int) -> str:
        """Get color based on temperature."""
        if temp_c >= 30:
            return IRCColors.RED
        elif temp_c >= 20:
            return IRCColors.ORANGE
        elif temp_c >= 10:
            return IRCColors.YELLOW
        elif temp_c >= 0:
            return IRCColors.LIGHT_CYAN
        else:
            return IRCColors.LIGHT_BLUE


class Sanitizer:
    """Input sanitization to prevent IRC injection and API abuse."""

    # Max lengths for various inputs
    MAX_LOCATION_LEN = 80
    MAX_TERM_LEN = 100
    MAX_QUOTE_LEN = 400
    MAX_NICK_LEN = 30
    MAX_GENERIC_LEN = 200

    # IRC control characters to strip from user input
    IRC_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f]')

    # Only allow safe characters in location/search queries
    SAFE_TEXT_RE = re.compile(r'[^\w\s\-.,\'\"!?@#&()/:;+]', re.UNICODE)

    # Valid IRC nick pattern
    NICK_RE = re.compile(r'^[A-Za-z_\[\]\\`^{}|][A-Za-z0-9_\[\]\\`^{}|\-]{0,29}$')

    # CRLF injection pattern
    CRLF_RE = re.compile(r'[\r\n]')

    @staticmethod
    def strip_irc_controls(text: str) -> str:
        """Remove IRC control characters from user input."""
        return Sanitizer.IRC_CONTROL_RE.sub('', text)

    @staticmethod
    def sanitize_location(location: str) -> Optional[str]:
        """Sanitize a location string for API queries."""
        location = Sanitizer.strip_irc_controls(location).strip()
        if not location or len(location) > Sanitizer.MAX_LOCATION_LEN:
            return None
        # Remove anything that isn't word chars, spaces, basic punctuation
        location = Sanitizer.SAFE_TEXT_RE.sub('', location).strip()
        return location if location else None

    @staticmethod
    def sanitize_term(term: str) -> Optional[str]:
        """Sanitize a search term."""
        term = Sanitizer.strip_irc_controls(term).strip()
        if not term or len(term) > Sanitizer.MAX_TERM_LEN:
            return None
        return term

    @staticmethod
    def sanitize_nick(nick: str) -> Optional[str]:
        """Validate and sanitize an IRC nickname."""
        nick = Sanitizer.strip_irc_controls(nick).strip()
        if not nick or len(nick) > Sanitizer.MAX_NICK_LEN:
            return None
        if not Sanitizer.NICK_RE.match(nick):
            return None
        return nick

    @staticmethod
    def sanitize_quote(text: str) -> Optional[str]:
        """Sanitize a quote string."""
        text = Sanitizer.strip_irc_controls(text).strip()
        if not text or len(text) > Sanitizer.MAX_QUOTE_LEN:
            return None
        return text

    @staticmethod
    def sanitize_generic(text: str) -> Optional[str]:
        """Sanitize generic user text input."""
        text = Sanitizer.strip_irc_controls(text).strip()
        if not text or len(text) > Sanitizer.MAX_GENERIC_LEN:
            return None
        return text

    @staticmethod
    def sanitize_irc_output(text: str) -> str:
        """Prevent CRLF injection in outgoing IRC messages."""
        return Sanitizer.CRLF_RE.sub('', text)

    @staticmethod
    def safe_url_param(param: str) -> str:
        """URL-encode a parameter for safe use in API URLs."""
        return urllib.parse.quote(param, safe='')


class IRCBot:
    def __init__(self, server: str, port: int, nickname: str, channels: list,
                 use_ssl: bool = False, password: Optional[str] = None,
                 command_prefix: str = "%"):
        self.server = server
        self.port = port
        self.nickname = nickname
        self.channels = channels
        self.use_ssl = use_ssl
        self.password = password
        self.command_prefix = command_prefix
        self.irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.start_time = time.time()

        # Precomputed colored middot separator
        C = IRCColors
        self._dot = f" {C.BOLD}{C.CYAN}\xb7{C.RESET} "

        # API endpoints
        self.geocoding_api = "https://geocoding-api.open-meteo.com/v1/search?name={location}&count=1&language=en&format=json"
        self.openmeteo_api = (
            "https://api.open-meteo.com/v1/forecast?"
            "latitude={lat}&longitude={lon}"
            "&current=temperature_2m,relative_humidity_2m,apparent_temperature,"
            "weather_code,wind_speed_10m,wind_direction_10m,pressure_msl,cloud_cover,visibility"
            "&daily=weather_code,temperature_2m_max,temperature_2m_min,sunrise,sunset,"
            "precipitation_sum,precipitation_probability_max"
            "&temperature_unit=celsius&wind_speed_unit=kmh&forecast_days=3&timezone=auto"
        )

        # Track last seen users
        self.seen_users = {}

        # Quote database
        self.quotes = []

        # 8ball responses
        self.eightball_responses = [
            "It is certain", "It is decidedly so", "Without a doubt", "Yes definitely",
            "You may rely on it", "As I see it, yes", "Most likely", "Outlook good",
            "Yes", "Signs point to yes", "Reply hazy, try again", "Ask again later",
            "Better not tell you now", "Cannot predict now", "Concentrate and ask again",
            "Don't count on it", "My reply is no", "My sources say no", "Outlook not so good",
            "Very doubtful"
        ]

        # Fun facts
        self.facts = [
            "Honey never spoils. Archaeologists have found 3000-year-old honey in Egyptian tombs that was still edible.",
            "Octopuses have three hearts and blue blood.",
            "A group of flamingos is called a 'flamboyance'.",
            "The shortest war in history lasted 38 minutes (Britain vs Zanzibar, 1896).",
            "Bananas are berries, but strawberries aren't.",
            "There are more possible iterations of a game of chess than atoms in the observable universe.",
            "A day on Venus is longer than a year on Venus.",
            "The inventor of the Pringles can is buried in one.",
            "Wombat poop is cube-shaped.",
            "The heart of a shrimp is located in its head.",
            "A jiffy is an actual unit of time: 1/100th of a second.",
            "The total weight of ants on earth once equaled the total weight of people.",
            "An octopus has nine brains.",
            "Cows have best friends and get stressed when separated.",
            "Hot water freezes faster than cold water. This is called the Mpemba effect.",
        ]

        # Weather code descriptions
        self.weather_codes = {
            0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast",
            45: "Foggy", 48: "Depositing rime fog",
            51: "Light drizzle", 53: "Moderate drizzle", 55: "Dense drizzle",
            61: "Slight rain", 63: "Moderate rain", 65: "Heavy rain",
            71: "Slight snow", 73: "Moderate snow", 75: "Heavy snow",
            77: "Snow grains", 80: "Slight rain showers", 81: "Moderate rain showers",
            82: "Violent rain showers", 85: "Slight snow showers", 86: "Heavy snow showers",
            95: "Thunderstorm", 96: "Thunderstorm w/ slight hail", 99: "Thunderstorm w/ heavy hail"
        }

        # Per-user rate limiting
        self.user_last_cmd = {}
        self.rate_limit_seconds = 2

    # ─── Formatting helpers ────────────────────────────────────────

    def _tag(self, *parts) -> str:
        """Tag line: le0 · part1 · part2 -- bright cyan middots."""
        C = IRCColors
        bot = f"{C.BOLD}{C.CYAN}le0{C.RESET}"
        return bot + self._dot + self._dot.join(str(p) for p in parts)

    def _sub(self, text: str) -> str:
        """Sub-line:   > text -- cyan arrow."""
        C = IRCColors
        arrow = f"{C.BOLD}{C.CYAN}>{C.RESET}"
        return f"  {arrow} {text}"

    def _err(self, text: str) -> str:
        """Error line: le0 · err · message -- red text."""
        C = IRCColors
        bot = f"{C.BOLD}{C.CYAN}le0{C.RESET}"
        err_label = f"{C.BOLD}{C.RED}err{C.RESET}"
        err_text = f"{C.RED}{text}{C.RESET}"
        return f"{bot}{self._dot}{err_label}{self._dot}{err_text}"

    def _ok(self, text: str) -> str:
        """Success line: le0 · ok · message -- green text."""
        C = IRCColors
        bot = f"{C.BOLD}{C.CYAN}le0{C.RESET}"
        ok_label = f"{C.BOLD}{C.GREEN}ok{C.RESET}"
        ok_text = f"{C.GREEN}{text}{C.RESET}"
        return f"{bot}{self._dot}{ok_label}{self._dot}{ok_text}"

    def _bar(self, pct: int, width: int = 10) -> str:
        """Percentage bar with colored fill: [####------] 65%"""
        C = IRCColors
        clamped = max(0, min(100, pct))
        filled = round(clamped * width / 100)
        empty = width - filled
        fill_str = C.color('#' * filled, C.GREEN)
        empty_str = C.color('-' * empty, C.GREY)
        pct_str = C.bold(C.color(f"{pct}%", C.YELLOW))
        return f"[{fill_str}{empty_str}] {pct_str}"

    def _cat(self, name: str, color: str) -> str:
        """Color a category name: bold + colored."""
        return IRCColors.bold(IRCColors.color(name, color))

    # ─── Rate limiting ────────────────────────────────────────────

    def _check_rate_limit(self, nick: str) -> bool:
        """Check if a user is rate-limited. Returns True if allowed."""
        now = time.time()
        last = self.user_last_cmd.get(nick.lower(), 0)
        if now - last < self.rate_limit_seconds:
            return False
        self.user_last_cmd[nick.lower()] = now
        return True

    # ─── Connection ───────────────────────────────────────────────

    def connect(self):
        """Connect to the IRC server."""
        print(f"Connecting to {self.server}:{self.port}...")

        if self.use_ssl:
            context = ssl.create_default_context()
            self.irc = context.wrap_socket(self.irc, server_hostname=self.server)

        self.irc.connect((self.server, self.port))

        if self.password:
            self.send_raw(f"PASS {self.password}")

        self.send_raw(f"NICK {self.nickname}")
        self.send_raw(f"USER {self.nickname} 0 * :{self.nickname}")
        print("Connected!")

    def send_raw(self, message: str):
        """Send a raw IRC message."""
        # Prevent CRLF injection in raw messages
        message = Sanitizer.sanitize_irc_output(message)
        self.irc.send(bytes(message + "\r\n", "UTF-8"))

    def send_message(self, target: str, message: str):
        """Send a message to a channel or user."""
        # Sanitize output to prevent injection
        message = Sanitizer.sanitize_irc_output(message)
        self.send_raw(f"PRIVMSG {target} :{message}")

    def join_channel(self, channel: str):
        """Join a channel."""
        self.send_raw(f"JOIN {channel}")
        print(f"Joined {channel}")

    # ─── Weather ──────────────────────────────────────────────────

    def get_weather(self, location: str) -> str:
        """Get weather information for a location."""
        try:
            C = IRCColors
            d = self._dot

            safe_location = Sanitizer.safe_url_param(location)
            geocode_url = self.geocoding_api.format(location=safe_location)
            geo_response = requests.get(geocode_url, timeout=5)

            if geo_response.status_code != 200:
                return self._err(f"could not find location '{location}'")

            geo_data = geo_response.json()
            if not geo_data.get('results'):
                return self._err(f"could not find location '{location}'")

            result = geo_data['results'][0]
            lat = result['latitude']
            lon = result['longitude']
            city_name = result['name']
            country = result.get('country', '')

            weather_url = self.openmeteo_api.format(lat=lat, lon=lon)
            weather_response = requests.get(weather_url, timeout=5)

            if weather_response.status_code != 200:
                return self._err("error fetching weather data")

            data = weather_response.json()
            current = data['current']
            daily = data['daily']

            temp_c = int(current['temperature_2m'])
            temp_f = int(temp_c * 9/5 + 32)
            feels_c = int(current['apparent_temperature'])
            feels_f = int(feels_c * 9/5 + 32)
            humidity = int(current['relative_humidity_2m'])
            wind_speed = int(current['wind_speed_10m'])
            wind_dir = int(current['wind_direction_10m'])
            pressure = int(current['pressure_msl'])
            cloud_cover = int(current['cloud_cover'])
            visibility = current.get('visibility', 0)
            visibility_km = int(visibility / 1000) if visibility else 0
            weather_code = current['weather_code']

            sunrise = daily['sunrise'][0].split('T')[1][:5] if daily.get('sunrise') else 'N/A'
            sunset = daily['sunset'][0].split('T')[1][:5] if daily.get('sunset') else 'N/A'

            desc = self.weather_codes.get(weather_code, "Unknown")

            directions = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE',
                          'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW']
            wind_compass = directions[int((wind_dir + 11.25) / 22.5) % 16]

            temp_color = C.temp_color(temp_c)
            feels_color = C.temp_color(feels_c)

            location_display = f"{city_name}, {country}" if country else city_name

            tc = C.bold(C.color(f"{temp_c}C", temp_color))
            tf = C.bold(C.color(f"{temp_f}F", temp_color))
            fc = C.color(f"{feels_c}C", feels_color)
            ff = C.color(f"{feels_f}F", feels_color)
            desc_text = C.bold(C.color(desc, C.WHITE))
            wind_text = C.color(f"{wind_speed}km/h", C.LIGHT_GREEN)
            wind_dir_text = C.bold(C.color(wind_compass, C.LIGHT_GREEN))
            press_text = C.color(f"{pressure}hPa", C.LIGHT_GREY)
            vis_text = C.color(f"{visibility_km}km", C.LIGHT_CYAN)
            rise_text = C.bold(C.color(sunrise, C.YELLOW))
            set_text = C.bold(C.color(sunset, C.ORANGE))

            humid_bar = self._bar(humidity)
            cloud_bar = self._bar(cloud_cover)

            cat = self._cat("weather", C.LIGHT_BLUE)
            loc_text = C.bold(location_display)
            line1 = self._tag(cat, loc_text)
            line2 = self._sub(f"{desc_text}{d}{tc}/{tf}{d}{C.bold('feels')} {fc}/{ff}")
            line3 = self._sub(f"{C.bold('humid')} {humid_bar}{d}{C.bold('wind')} {wind_text} {wind_dir_text}{d}{C.bold('cloud')} {cloud_bar}")
            line4 = self._sub(f"{press_text}{d}{C.bold('vis')} {vis_text}{d}{C.bold('sun')} {rise_text}-{set_text}")

            return f"{line1}\n{line2}\n{line3}\n{line4}"

        except requests.exceptions.Timeout:
            return self._err("request timed out - weather service may be unavailable")
        except requests.exceptions.RequestException:
            return self._err("network error while fetching weather")
        except (KeyError, IndexError, ValueError):
            return self._err("error parsing weather data")

    def get_forecast(self, location: str, days: int = 3) -> list:
        """Get weather forecast for a location."""
        try:
            C = IRCColors
            d = self._dot

            safe_location = Sanitizer.safe_url_param(location)
            geocode_url = self.geocoding_api.format(location=safe_location)
            geo_response = requests.get(geocode_url, timeout=5)

            if geo_response.status_code != 200:
                return [self._err(f"could not find location '{location}'")]

            geo_data = geo_response.json()
            if not geo_data.get('results'):
                return [self._err(f"could not find location '{location}'")]

            result = geo_data['results'][0]
            lat = result['latitude']
            lon = result['longitude']
            city_name = result['name']
            country = result.get('country', '')

            weather_url = self.openmeteo_api.format(lat=lat, lon=lon)
            weather_response = requests.get(weather_url, timeout=5)

            if weather_response.status_code != 200:
                return [self._err("error fetching forecast data")]

            data = weather_response.json()
            daily = data['daily']

            location_display = f"{city_name}, {country}" if country else city_name
            cat = self._cat("forecast", C.LIGHT_BLUE)
            forecasts = [self._tag(cat, C.bold(location_display))]

            for i in range(min(days, 3)):
                date = daily['time'][i]
                max_temp_c = int(daily['temperature_2m_max'][i])
                min_temp_c = int(daily['temperature_2m_min'][i])
                max_temp_f = int(max_temp_c * 9/5 + 32)
                min_temp_f = int(min_temp_c * 9/5 + 32)
                weather_code = daily['weather_code'][i]
                desc = self.weather_codes.get(weather_code, "Unknown")

                precip_sum = daily.get('precipitation_sum', [0])[i]
                precip_prob = daily.get('precipitation_probability_max', [0])[i]

                max_color = C.temp_color(max_temp_c)
                min_color = C.temp_color(min_temp_c)

                date_text = C.bold(C.color(date, C.CYAN))
                desc_text = C.color(desc, C.WHITE)
                hi_c = C.bold(C.color(f"{max_temp_c}C", max_color))
                hi_f = C.bold(C.color(f"{max_temp_f}F", max_color))
                lo_c = C.color(f"{min_temp_c}C", min_color)
                lo_f = C.color(f"{min_temp_f}F", min_color)
                rain_text = C.color(f"{precip_sum:.1f}mm", C.LIGHT_BLUE)
                rain_pct = C.color(f"{precip_prob}%", C.CYAN)

                forecast_line = self._sub(
                    f"{date_text}{d}{desc_text}{d}{C.bold('hi')} {hi_c}/{hi_f}{d}"
                    f"{C.bold('lo')} {lo_c}/{lo_f}{d}{C.bold('rain')} {rain_text} ({rain_pct})"
                )
                forecasts.append(forecast_line)

            return forecasts

        except requests.exceptions.Timeout:
            return [self._err("request timed out - weather service may be unavailable")]
        except requests.exceptions.RequestException:
            return [self._err("network error while fetching forecast")]
        except (KeyError, IndexError, ValueError):
            return [self._err("error parsing forecast data")]

    # ─── Info Commands ────────────────────────────────────────────

    def get_time(self, location: str = None) -> str:
        """Get current time."""
        C = IRCColors
        try:
            cat = self._cat("time", C.LIGHT_CYAN)
            if location:
                safe_location = Sanitizer.safe_url_param(location)
                geocode_url = self.geocoding_api.format(location=safe_location)
                geo_response = requests.get(geocode_url, timeout=5)

                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('results'):
                        current_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                        return self._tag(cat, C.bold(current_time))

                return self._err(f"could not find location '{location}'")
            else:
                current_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                return self._tag(cat, C.bold(current_time))

        except Exception:
            return self._err("error getting time")

    def get_urban_definition(self, term: str) -> str:
        """Get Urban Dictionary definition."""
        C = IRCColors
        try:
            safe_term = Sanitizer.safe_url_param(term)
            response = requests.get(
                f"https://api.urbandictionary.com/v0/define?term={safe_term}",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if data['list']:
                    definition = data['list'][0]
                    word = definition['word']
                    meaning = definition['definition'].replace('[', '').replace(']', '')
                    if len(meaning) > 300:
                        meaning = meaning[:297] + "..."

                    cat = self._cat("urban", C.ORANGE)
                    word_text = C.bold(C.color(word, C.YELLOW))
                    return f"{self._tag(cat, word_text)}\n{self._sub(C.color(meaning, C.LIGHT_GREY))}"
                else:
                    return self._err(f"no definition found for '{term}'")
            else:
                return self._err("error fetching definition")

        except Exception:
            return self._err("error looking up definition")

    # ─── Fun Commands ─────────────────────────────────────────────

    def coin_flip(self) -> str:
        """Flip a coin."""
        C = IRCColors
        result = random.choice(["HEADS", "TAILS"])
        color = C.YELLOW if result == "HEADS" else C.LIGHT_GREY
        cat = self._cat("flip", C.YELLOW)
        return self._tag(cat, C.bold(C.color(result, color)))

    def roll_dice(self, dice_str: str = "1d6") -> str:
        """Roll dice (e.g., 2d6, 1d20)."""
        C = IRCColors
        try:
            if 'd' not in dice_str.lower():
                dice_str = f"1d{dice_str}"

            num, sides = dice_str.lower().split('d')
            num = int(num) if num else 1
            sides = int(sides)

            if num < 1 or sides < 1:
                return self._err("dice values must be positive")
            if num > 20 or sides > 1000:
                return self._err("max 20 dice with 1000 sides each")

            rolls = [random.randint(1, sides) for _ in range(num)]
            total = sum(rolls)

            cat = self._cat("dice", C.CYAN)
            dice_label = C.bold(f"{num}d{sides}")
            total_text = C.bold(C.color(str(total), C.YELLOW))

            if num == 1:
                return self._tag(cat, f"{dice_label} > {total_text}")
            else:
                rolls_text = C.color(str(rolls), C.LIGHT_GREY)
                return self._tag(cat, f"{dice_label} > {rolls_text} = {total_text}")

        except (ValueError, OverflowError):
            return self._err("invalid dice format (use: 2d6, 1d20)")

    def eightball(self, question: str) -> str:
        """Magic 8-ball."""
        C = IRCColors
        if not question.strip():
            return self._err("ask me a question!")

        response = random.choice(self.eightball_responses)
        cat = self._cat("8ball", C.PURPLE)
        return self._tag(cat, C.bold(C.color(response, C.PURPLE)))

    def rps(self, choice: str) -> str:
        """Rock Paper Scissors."""
        C = IRCColors
        choices = ['rock', 'paper', 'scissors']
        choice = choice.lower().strip()

        aliases = {'r': 'rock', 'p': 'paper', 's': 'scissors'}
        choice = aliases.get(choice, choice)

        if choice not in choices:
            return self._err("choose: rock, paper, or scissors (r/p/s)")

        bot_choice = random.choice(choices)

        if choice == bot_choice:
            result = C.bold(C.color("draw", C.YELLOW))
        elif (choice == 'rock' and bot_choice == 'scissors') or \
             (choice == 'paper' and bot_choice == 'rock') or \
             (choice == 'scissors' and bot_choice == 'paper'):
            result = C.bold(C.color("you win", C.GREEN))
        else:
            result = C.bold(C.color("you lose", C.RED))

        cat = self._cat("rps", C.ORANGE)
        you_text = C.bold(C.color(choice.upper(), C.CYAN))
        bot_text = C.bold(C.color(bot_choice.upper(), C.ORANGE))
        return self._tag(cat, f"{you_text} vs {bot_text}", result)

    def get_fact(self) -> str:
        """Get a random fun fact."""
        C = IRCColors
        fact = random.choice(self.facts)
        cat = self._cat("fact", C.LIGHT_GREEN)
        return f"{self._tag(cat)}\n{self._sub(C.color(fact, C.LIGHT_GREY))}"

    # ─── Utility Commands ─────────────────────────────────────────

    def track_seen(self, nick: str, channel: str, message: str):
        """Track when users were last seen."""
        self.seen_users[nick.lower()] = {
            'nick': nick,
            'channel': channel,
            'message': message[:100],
            'time': time.time()
        }

    def get_seen(self, nick: str) -> str:
        """Get when a user was last seen."""
        C = IRCColors
        nick_lower = nick.lower()
        if nick_lower in self.seen_users:
            user = self.seen_users[nick_lower]
            elapsed = int(time.time() - user['time'])

            if elapsed < 60:
                time_str = f"{elapsed}s ago"
            elif elapsed < 3600:
                time_str = f"{elapsed // 60}m ago"
            elif elapsed < 86400:
                time_str = f"{elapsed // 3600}h ago"
            else:
                time_str = f"{elapsed // 86400}d ago"

            cat = self._cat("seen", C.CYAN)
            nick_text = C.bold(C.color(user['nick'], C.WHITE))
            time_text = C.bold(C.color(time_str, C.YELLOW))
            chan_text = C.color(user['channel'], C.LIGHT_GREEN)
            line1 = self._tag(cat, nick_text, f"{time_text} in {chan_text}")
            msg = user['message']
            line2 = self._sub(C.color(f'"{msg}"', C.LIGHT_GREY))
            return f"{line1}\n{line2}"
        else:
            return self._err(f"haven't seen {nick} yet")

    def add_quote(self, quote: str, added_by: str) -> str:
        """Add a quote to the database."""
        self.quotes.append({
            'quote': quote,
            'added_by': added_by,
            'timestamp': time.time()
        })
        quote_num = len(self.quotes)
        return self._ok(f"quote #{quote_num} added")

    def get_random_quote(self) -> str:
        """Get a random quote."""
        C = IRCColors
        if not self.quotes:
            return self._err("no quotes stored yet -- use %addquote to add one")

        quote_data = random.choice(self.quotes)
        quote_num = self.quotes.index(quote_data) + 1
        cat = self._cat(f"quote #{quote_num}", C.PINK)
        line1 = self._tag(cat)
        quote_text = quote_data['quote']
        added_by = quote_data['added_by']
        qt = C.color(f'"{quote_text}"', C.LIGHT_GREY)
        by = C.bold(C.color(added_by, C.CYAN))
        line2 = self._sub(f"{qt}{self._dot}added by {by}")
        return f"{line1}\n{line2}"

    def get_uptime(self) -> str:
        """Get bot uptime."""
        C = IRCColors
        elapsed = int(time.time() - self.start_time)
        days = elapsed // 86400
        hours = (elapsed % 86400) // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")

        uptime_str = " ".join(parts)
        cat = self._cat("uptime", C.LIGHT_GREEN)
        return self._tag(cat, C.bold(C.color(uptime_str, C.LIGHT_GREEN)))

    def do_ping(self) -> str:
        """Return a pong with timestamp."""
        C = IRCColors
        ts = time.strftime("%H:%M:%S", time.gmtime())
        cat = self._cat("pong", C.LIGHT_CYAN)
        return self._tag(cat, C.bold(C.color(ts, C.LIGHT_CYAN)))

    def hash_text(self, text: str) -> str:
        """Hash text with multiple algorithms."""
        C = IRCColors
        md5 = hashlib.md5(text.encode()).hexdigest()
        sha1 = hashlib.sha1(text.encode()).hexdigest()
        sha256 = hashlib.sha256(text.encode()).hexdigest()
        sha256_short = sha256[:32] + "..."

        cat = self._cat("hash", C.LIGHT_GREY)
        md5_label = C.bold(C.color("md5", C.CYAN))
        sha1_label = C.bold(C.color("sha1", C.CYAN))
        sha256_label = C.bold(C.color("sha256", C.CYAN))
        md5_val = C.color(md5, C.LIGHT_GREY)
        sha1_val = C.color(sha1, C.LIGHT_GREY)
        sha256_val = C.color(sha256_short, C.LIGHT_GREY)

        line1 = self._tag(cat)
        line2 = self._sub(f"{md5_label}    {md5_val}")
        line3 = self._sub(f"{sha1_label}   {sha1_val}")
        line4 = self._sub(f"{sha256_label} {sha256_val}")
        return f"{line1}\n{line2}\n{line3}\n{line4}"

    def do_base64(self, mode: str, text: str) -> str:
        """Encode or decode base64."""
        C = IRCColors
        try:
            if mode in ('e', 'encode', 'enc'):
                result = base64.b64encode(text.encode()).decode()
                cat = self._cat("b64enc", C.LIGHT_BLUE)
                return f"{self._tag(cat)}\n{self._sub(C.color(result, C.LIGHT_GREY))}"
            elif mode in ('d', 'decode', 'dec'):
                result = base64.b64decode(text.encode()).decode('utf-8', errors='replace')
                # Sanitize decoded output
                result = Sanitizer.strip_irc_controls(result)[:300]
                cat = self._cat("b64dec", C.LIGHT_BLUE)
                return f"{self._tag(cat)}\n{self._sub(C.color(result, C.LIGHT_GREY))}"
            else:
                return self._err("usage: %base64 <encode|decode> <text>")
        except Exception:
            return self._err("invalid base64 input")

    def reverse_text(self, text: str) -> str:
        """Reverse a string."""
        C = IRCColors
        reversed_text = text[::-1]
        cat = self._cat("reverse", C.YELLOW)
        return self._tag(cat, C.bold(C.color(reversed_text, C.LIGHT_GREY)))

    def mock_text(self, text: str) -> str:
        """SpOnGeBoB mOcKiNg CaSe."""
        C = IRCColors
        result = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(text)
        )
        cat = self._cat("mock", C.YELLOW)
        return self._tag(cat, C.bold(C.color(result, C.YELLOW)))

    def safe_calc(self, expr: str) -> str:
        """Safely evaluate a math expression."""
        C = IRCColors
        # Whitelist: only digits, operators, parens, decimal points, spaces
        if not re.match(r'^[\d\s+\-*/().,%^]+$', expr):
            return self._err("invalid expression -- only numbers and +-*/()^. allowed")

        # Replace ^ with ** for exponentiation
        expr = expr.replace('^', '**')

        # Safety: reject if too long or nested
        if len(expr) > 100:
            return self._err("expression too long")

        # Prevent extremely large exponents
        if '**' in expr:
            # Check each exponent isn't too large
            parts = expr.split('**')
            for part in parts[1:]:
                # Extract the number right after **
                num_match = re.match(r'\s*(\d+)', part)
                if num_match and int(num_match.group(1)) > 1000:
                    return self._err("exponent too large (max 1000)")

        try:
            # Use eval with no builtins for safety
            result = eval(expr, {"__builtins__": {}}, {})
            if isinstance(result, float):
                # Avoid printing huge floats
                if abs(result) > 1e15 or (result != 0 and abs(result) < 1e-10):
                    result = f"{result:.6e}"
                else:
                    result = f"{result:.6f}".rstrip('0').rstrip('.')

            cat = self._cat("calc", C.GREEN)
            expr_text = C.color(str(expr), C.LIGHT_GREY)
            result_text = C.bold(C.color(str(result), C.GREEN))
            return self._tag(cat, f"{expr_text} = {result_text}")
        except ZeroDivisionError:
            return self._err("division by zero")
        except Exception:
            return self._err("could not evaluate expression")

    # ─── Command Handler ──────────────────────────────────────────

    def handle_command(self, channel: str, nick: str, message: str):
        """Handle bot commands."""
        # Rate limit check
        if not self._check_rate_limit(nick):
            return

        parts = message.strip().split()
        if not parts:
            return

        command = parts[0].lower()
        p = self.command_prefix

        # ── Weather ──
        if command in (f"{p}weather", f"{p}w"):
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}weather <location>"))
                return
            location = Sanitizer.sanitize_location(" ".join(parts[1:]))
            if not location:
                self.send_message(channel, self._err("invalid location"))
                return
            weather = self.get_weather(location)
            for line in weather.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.3)

        elif command in (f"{p}forecast", f"{p}f"):
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}forecast <location>"))
                return
            location = Sanitizer.sanitize_location(" ".join(parts[1:]))
            if not location:
                self.send_message(channel, self._err("invalid location"))
                return
            forecasts = self.get_forecast(location, 3)
            for forecast in forecasts:
                self.send_message(channel, forecast)
                time.sleep(0.5)

        # ── Info ──
        elif command in (f"{p}urban", f"{p}ud"):
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}urban <term>"))
                return
            term = Sanitizer.sanitize_term(" ".join(parts[1:]))
            if not term:
                self.send_message(channel, self._err("invalid search term"))
                return
            result = self.get_urban_definition(term)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.3)

        elif command == f"{p}time":
            location = None
            if len(parts) > 1:
                location = Sanitizer.sanitize_location(" ".join(parts[1:]))
            result = self.get_time(location)
            self.send_message(channel, result)

        # ── Fun ──
        elif command in (f"{p}coin", f"{p}flip"):
            self.send_message(channel, self.coin_flip())

        elif command in (f"{p}roll", f"{p}dice"):
            dice_str = parts[1] if len(parts) > 1 else "1d6"
            # Sanitize dice input: only allow digits and 'd'
            if not re.match(r'^\d{0,3}d?\d{1,4}$', dice_str.lower()):
                self.send_message(channel, self._err("invalid dice format (use: 2d6, 1d20)"))
                return
            self.send_message(channel, self.roll_dice(dice_str))

        elif command in (f"{p}8ball", f"{p}8"):
            question = " ".join(parts[1:])
            self.send_message(channel, self.eightball(question))

        elif command in (f"{p}rps",):
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}rps <rock|paper|scissors>"))
                return
            self.send_message(channel, self.rps(parts[1]))

        elif command == f"{p}fact":
            result = self.get_fact()
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.3)

        # ── Utility ──
        elif command == f"{p}seen":
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}seen <nick>"))
                return
            target_nick = Sanitizer.sanitize_nick(parts[1])
            if not target_nick:
                self.send_message(channel, self._err("invalid nickname"))
                return
            result = self.get_seen(target_nick)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command == f"{p}addquote":
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}addquote <quote>"))
                return
            quote = Sanitizer.sanitize_quote(" ".join(parts[1:]))
            if not quote:
                self.send_message(channel, self._err("invalid quote (too long or empty)"))
                return
            result = self.add_quote(quote, nick)
            self.send_message(channel, result)

        elif command == f"{p}quote":
            result = self.get_random_quote()
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command == f"{p}uptime":
            self.send_message(channel, self.get_uptime())

        elif command == f"{p}ping":
            self.send_message(channel, self.do_ping())

        elif command == f"{p}calc":
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}calc <expression>"))
                return
            expr = " ".join(parts[1:])
            self.send_message(channel, self.safe_calc(expr))

        elif command == f"{p}hash":
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}hash <text>"))
                return
            text = Sanitizer.sanitize_generic(" ".join(parts[1:]))
            if not text:
                self.send_message(channel, self._err("invalid input"))
                return
            result = self.hash_text(text)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command in (f"{p}base64", f"{p}b64"):
            if len(parts) < 3:
                self.send_message(channel, self._err(f"usage: {p}base64 <encode|decode> <text>"))
                return
            mode = parts[1].lower()
            text = Sanitizer.sanitize_generic(" ".join(parts[2:]))
            if not text:
                self.send_message(channel, self._err("invalid input"))
                return
            result = self.do_base64(mode, text)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command == f"{p}reverse":
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}reverse <text>"))
                return
            text = Sanitizer.sanitize_generic(" ".join(parts[1:]))
            if not text:
                self.send_message(channel, self._err("invalid input"))
                return
            self.send_message(channel, self.reverse_text(text))

        elif command == f"{p}mock":
            if len(parts) < 2:
                self.send_message(channel, self._err(f"usage: {p}mock <text>"))
                return
            text = Sanitizer.sanitize_generic(" ".join(parts[1:]))
            if not text:
                self.send_message(channel, self._err("invalid input"))
                return
            self.send_message(channel, self.mock_text(text))

        # ── Help ──
        elif command == f"{p}help":
            C = IRCColors
            cat = self._cat("commands", C.YELLOW)
            lines = [
                self._tag(cat),
                self._sub(C.color("weather/w \xb7 forecast/f \xb7 urban/ud \xb7 time", C.LIGHT_BLUE)),
                self._sub(C.color("coin/flip \xb7 roll/dice \xb7 8ball/8 \xb7 rps \xb7 fact", C.YELLOW)),
                self._sub(C.color("quote \xb7 addquote \xb7 seen \xb7 ping \xb7 uptime", C.LIGHT_GREEN)),
                self._sub(C.color("calc \xb7 hash \xb7 base64/b64 \xb7 reverse \xb7 mock", C.LIGHT_CYAN)),
            ]
            for line in lines:
                self.send_message(channel, line)
                time.sleep(0.3)

    # ─── Main Loop ────────────────────────────────────────────────

    def run(self):
        """Main bot loop."""
        self.connect()

        buffer = ""
        connected = False

        print("Waiting for server connection to complete...")
        while not connected:
            try:
                buffer += self.irc.recv(2048).decode("UTF-8", errors="ignore")
                lines = buffer.split("\r\n")
                buffer = lines.pop()

                for line in lines:
                    print(line)

                    if line.startswith("PING"):
                        pong = line.replace("PING", "PONG", 1)
                        self.send_raw(pong)

                    if " 376 " in line or " 422 " in line:
                        connected = True
                        print("\nConnection established! Joining channels...")
                        for channel in self.channels:
                            self.join_channel(channel)
                        break

            except Exception as e:
                print(f"Error during connection: {e}")
                time.sleep(1)

        buffer = ""

        while True:
            try:
                buffer += self.irc.recv(2048).decode("UTF-8", errors="ignore")
                lines = buffer.split("\r\n")
                buffer = lines.pop()

                for line in lines:
                    print(line)

                    if line.startswith("PING"):
                        pong = line.replace("PING", "PONG", 1)
                        self.send_raw(pong)
                        continue

                    # Parse messages: :nick!user@host PRIVMSG #channel :message
                    match = re.match(r':(.+?)!.+? PRIVMSG (.+?) :(.+)', line)

                    if match:
                        nick = match.group(1)
                        channel = match.group(2)
                        message = match.group(3)

                        if nick == self.nickname:
                            continue

                        self.track_seen(nick, channel, message)

                        if message.startswith(self.command_prefix):
                            self.handle_command(channel, nick, message)

            except KeyboardInterrupt:
                print("\nShutting down...")
                self.send_raw("QUIT :le0 shutting down")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(5)


if __name__ == "__main__":
    bot = IRCBot(
        server="irc.blcknd.network",
        port=6697,
        nickname="le0",
        channels=["#d0mer"],
        use_ssl=True,
        password=None,
        command_prefix="%"
    )

    p = bot.command_prefix
    print("\n  le0 \xb7 irc bot v3.0")
    print("  " + "-" * 40)
    print(f"  weather/w \xb7 forecast/f \xb7 urban/ud \xb7 time")
    print(f"  coin/flip \xb7 roll/dice \xb7 8ball/8 \xb7 rps \xb7 fact")
    print(f"  quote \xb7 addquote \xb7 seen \xb7 ping \xb7 uptime")
    print(f"  calc \xb7 hash \xb7 base64/b64 \xb7 reverse \xb7 mock")
    print("  " + "-" * 40)
    print(f"  prefix: {p}  |  Ctrl+C to stop\n")

    bot.run()
