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


# ─── Enhanced Theme Constants ─────────────────────────────────────────

# Unicode box-drawing pieces
BOX_TL = "╔"
BOX_TR = "╗"
BOX_BL = "╚"
BOX_BR = "╝"
BOX_H  = "═"
BOX_V  = "║"
BOX_VR = "╠"
BOX_VL = "╣"
BOX_SEP = "•"
ARROW  = "▸"
BULLET = "◆"
DIVIDER = "─"
STAR = "★"
DOT = "●"

# Color shortcuts for cleaner code
C = IRCColors
B  = IRCColors.BOLD
R  = IRCColors.RESET

# Theme color palette
COLOR_PRIMARY = IRCColors.CYAN
COLOR_ACCENT = IRCColors.LIGHT_CYAN
COLOR_SUCCESS = IRCColors.LIGHT_GREEN
COLOR_ERROR = IRCColors.RED
COLOR_WARNING = IRCColors.ORANGE
COLOR_INFO = IRCColors.YELLOW
COLOR_LABEL = IRCColors.PURPLE
COLOR_VALUE = IRCColors.LIGHT_GREY


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

    # ─── Enhanced formatting helpers ───────────────────────────────

    def _header(self, text: str) -> str:
        """Enhanced header with box drawing."""
        return f"{B}{COLOR_PRIMARY}{BOX_TL}{BOX_H*2} {text} {BOX_H*2}{BOX_TR}{R}"

    def _footer(self, text: str = "") -> str:
        """Footer to close boxes."""
        if text:
            return f"{B}{COLOR_PRIMARY}{BOX_BL}{BOX_H*2} {text} {BOX_H*2}{BOX_BR}{R}"
        return f"{B}{COLOR_PRIMARY}{BOX_BL}{BOX_H*6}{BOX_BR}{R}"

    def _error(self, text: str) -> str:
        """Error message with icon."""
        return f"{B}{COLOR_ERROR}{BULLET}{R} {COLOR_ERROR}{text}{R}"

    def _success(self, text: str) -> str:
        """Success message with icon."""
        return f"{B}{COLOR_SUCCESS}{STAR}{R} {COLOR_SUCCESS}{text}{R}"

    def _info(self, text: str) -> str:
        """Info message with icon."""
        return f"{B}{COLOR_INFO}{DOT}{R} {COLOR_ACCENT}{text}{R}"

    def _arrow_line(self, text: str) -> str:
        """Arrow-prefixed line."""
        return f" {B}{COLOR_ACCENT}{ARROW}{R} {text}"

    def _label(self, text: str) -> str:
        """Colored label for field names."""
        return f"{B}{COLOR_LABEL}{text}{R}"

    def _value(self, text: str, color: str = None) -> str:
        """Colored value."""
        if color:
            return f"{color}{text}{R}"
        return f"{COLOR_VALUE}{text}{R}"

    def _temp_color(self, temp_c: int) -> str:
        """Get color code based on temperature (Celsius)."""
        if temp_c < 0:
            return IRCColors.LIGHT_BLUE  # Very cold
        elif temp_c < 10:
            return IRCColors.CYAN        # Cold
        elif temp_c < 15:
            return IRCColors.LIGHT_CYAN  # Cool
        elif temp_c < 20:
            return IRCColors.LIGHT_GREEN # Mild
        elif temp_c < 25:
            return IRCColors.GREEN       # Comfortable
        elif temp_c < 30:
            return IRCColors.YELLOW      # Warm
        elif temp_c < 35:
            return IRCColors.ORANGE      # Hot
        else:
            return IRCColors.RED         # Very hot

    def _humidity_color(self, humidity: int) -> str:
        """Get color code based on humidity percentage."""
        if humidity < 30:
            return IRCColors.ORANGE      # Too dry
        elif humidity < 60:
            return IRCColors.LIGHT_GREEN # Comfortable
        elif humidity < 80:
            return IRCColors.YELLOW      # Humid
        else:
            return IRCColors.CYAN        # Very humid

    def _wind_color(self, wind_speed: int) -> str:
        """Get color code based on wind speed (km/h)."""
        if wind_speed < 10:
            return IRCColors.LIGHT_GREEN # Calm
        elif wind_speed < 30:
            return IRCColors.YELLOW      # Moderate
        elif wind_speed < 50:
            return IRCColors.ORANGE      # Strong
        else:
            return IRCColors.RED         # Very strong

    def _cloud_color(self, cloud_cover: int) -> str:
        """Get color code based on cloud cover percentage."""
        if cloud_cover < 20:
            return IRCColors.YELLOW      # Clear
        elif cloud_cover < 50:
            return IRCColors.LIGHT_GREEN # Partly cloudy
        elif cloud_cover < 80:
            return IRCColors.LIGHT_CYAN  # Mostly cloudy
        else:
            return IRCColors.GREY        # Overcast

    def _precip_color(self, precip_mm: float) -> str:
        """Get color code based on precipitation amount (mm)."""
        if precip_mm < 1:
            return IRCColors.LIGHT_GREEN # Light/none
        elif precip_mm < 5:
            return IRCColors.CYAN        # Light rain
        elif precip_mm < 10:
            return IRCColors.LIGHT_BLUE  # Moderate rain
        else:
            return IRCColors.BLUE        # Heavy rain

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
        message = Sanitizer.sanitize_irc_output(message)
        self.irc.send(bytes(message + "\r\n", "UTF-8"))

    def send_message(self, target: str, message: str):
        """Send a message to a channel or user."""
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
            safe_location = Sanitizer.safe_url_param(location)
            geocode_url = self.geocoding_api.format(location=safe_location)
            geo_response = requests.get(geocode_url, timeout=5)

            if geo_response.status_code != 200:
                return self._error(f"Could not find location '{location}'")

            geo_data = geo_response.json()
            if not geo_data.get('results'):
                return self._error(f"Could not find location '{location}'")

            result = geo_data['results'][0]
            lat = result['latitude']
            lon = result['longitude']
            city_name = result['name']
            country = result.get('country', '')

            weather_url = self.openmeteo_api.format(lat=lat, lon=lon)
            weather_response = requests.get(weather_url, timeout=5)

            if weather_response.status_code != 200:
                return self._error("Error fetching weather data")

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

            location_display = f"{city_name}, {country}" if country else city_name

            # Temperature-based coloring
            temp_color = self._temp_color(temp_c)
            feels_color = self._temp_color(feels_c)
            temp_text = f"{B}{temp_color}{temp_c}°C{R} {COLOR_PRIMARY}/{R} {B}{temp_color}{temp_f}°F{R}"
            feels_text = f"{feels_color}{feels_c}°C{R} {COLOR_PRIMARY}/{R} {feels_color}{feels_f}°F{R}"
            desc_text = f"{B}{C.YELLOW}{desc}{R}"

            # Apply color helpers to all weather data
            humidity_color = self._humidity_color(humidity)
            wind_color = self._wind_color(wind_speed)
            cloud_color = self._cloud_color(cloud_cover)

            line1 = self._header(f"Weather {BOX_SEP} {B}{COLOR_ACCENT}{location_display}{R}")
            line2 = self._arrow_line(
                f"{self._label('Condition')}: {desc_text}  "
                f"{self._label('Temp')}: {temp_text}  "
                f"{self._label('Feels')}: {feels_text}"
            )
            line3 = self._arrow_line(
                f"{self._label('Humidity')}: {B}{humidity_color}{humidity}%{R}  "
                f"{self._label('Wind')}: {B}{wind_color}{wind_speed}km/h{R} {COLOR_ACCENT}{wind_compass}{R}  "
                f"{self._label('Clouds')}: {B}{cloud_color}{cloud_cover}%{R}"
            )
            line4 = self._arrow_line(
                f"{self._label('Pressure')}: {COLOR_VALUE}{pressure}hPa{R}  "
                f"{self._label('Visibility')}: {COLOR_VALUE}{visibility_km}km{R}  "
                f"{self._label('Sunrise')}: {B}{C.YELLOW}{sunrise}{R}  "
                f"{self._label('Sunset')}: {B}{C.ORANGE}{sunset}{R}"
            )

            return f"{line1}\n{line2}\n{line3}\n{line4}"

        except requests.exceptions.Timeout:
            return self._error("Request timed out - weather service may be unavailable")
        except requests.exceptions.RequestException:
            return self._error("Network error while fetching weather")
        except (KeyError, IndexError, ValueError):
            return self._error("Error parsing weather data")

    def get_forecast(self, location: str, days: int = 3) -> list:
        """Get weather forecast for a location."""
        try:
            safe_location = Sanitizer.safe_url_param(location)
            geocode_url = self.geocoding_api.format(location=safe_location)
            geo_response = requests.get(geocode_url, timeout=5)

            if geo_response.status_code != 200:
                return [self._error(f"Could not find location '{location}'")]

            geo_data = geo_response.json()
            if not geo_data.get('results'):
                return [self._error(f"Could not find location '{location}'")]

            result = geo_data['results'][0]
            lat = result['latitude']
            lon = result['longitude']
            city_name = result['name']
            country = result.get('country', '')

            weather_url = self.openmeteo_api.format(lat=lat, lon=lon)
            weather_response = requests.get(weather_url, timeout=5)

            if weather_response.status_code != 200:
                return [self._error("Error fetching forecast data")]

            data = weather_response.json()
            daily = data['daily']

            location_display = f"{city_name}, {country}" if country else city_name
            forecasts = [self._header(f"Forecast {BOX_SEP} {B}{COLOR_ACCENT}{location_display}{R}")]

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

                # Temperature-based coloring
                max_color = self._temp_color(max_temp_c)
                min_color = self._temp_color(min_temp_c)
                precip_color = self._precip_color(precip_sum)

                date_text = f"{B}{COLOR_INFO}{date}{R}"
                desc_text = f"{C.YELLOW}{desc}{R}"
                high_text = f"{B}{max_color}{max_temp_c}°C{R}{COLOR_PRIMARY}/{R}{B}{max_color}{max_temp_f}°F{R}"
                low_text = f"{min_color}{min_temp_c}°C{R}{COLOR_PRIMARY}/{R}{min_color}{min_temp_f}°F{R}"
                precip_text = f"{B}{precip_color}{precip_sum:.1f}mm{R}"
                precip_prob_text = f"{precip_color}{precip_prob}%{R}"

                forecast_msg = self._arrow_line(
                    f"{date_text} {BOX_SEP} {desc_text}  "
                    f"{self._label('High')}: {high_text}  "
                    f"{self._label('Low')}: {low_text}  "
                    f"{self._label('Rain')}: {precip_text} {COLOR_PRIMARY}({precip_prob_text}){R}"
                )
                forecasts.append(forecast_msg)

            return forecasts

        except requests.exceptions.Timeout:
            return [self._error("Request timed out - weather service may be unavailable")]
        except requests.exceptions.RequestException:
            return [self._error("Network error while fetching forecast")]
        except (KeyError, IndexError, ValueError):
            return [self._error("Error parsing forecast data")]

    # ─── Info Commands ────────────────────────────────────────────

    def get_time(self, location: str = None) -> str:
        """Get current time."""
        try:
            if location:
                safe_location = Sanitizer.safe_url_param(location)
                geocode_url = self.geocoding_api.format(location=safe_location)
                geo_response = requests.get(geocode_url, timeout=5)

                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('results'):
                        current_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                        return f"{self._header('Time')} {B}{C.YELLOW}{current_time}{R}"

                return self._error(f"Could not find location '{location}'")
            else:
                current_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                return f"{self._header('Time')} {B}{C.YELLOW}{current_time}{R}"

        except Exception:
            return self._error("Error getting time")

    def get_urban_definition(self, term: str) -> str:
        """Get Urban Dictionary definition."""
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

                    word_text = f"{B}{C.PINK}{word}{R}"
                    return f"{self._header('Urban Dictionary')}\n{self._arrow_line(f'{word_text} {COLOR_PRIMARY}{DIVIDER*3}{R} {COLOR_ACCENT}{meaning}{R}')}"
                else:
                    return self._error(f"No definition found for '{term}'")
            else:
                return self._error("Error fetching definition")

        except Exception:
            return self._error("Error looking up definition")

    # ─── Fun Commands ─────────────────────────────────────────────

    def coin_flip(self) -> str:
        """Flip a coin."""
        result = random.choice(["HEADS", "TAILS"])
        coin_color = C.YELLOW if result == "HEADS" else C.LIGHT_GREY
        art = (
            f"{coin_color}  _____  {R}\n"
            f"{coin_color} /     \\ {R}\n"
            f"{coin_color}|   {B}{'H' if result == 'HEADS' else 'T'}{R}{coin_color}   |{R}\n"
            f"{coin_color} \\_____/ {R}"
        )
        result_text = f"{B}{coin_color}{result}{R}"
        return f"{self._header('Coin Flip')}\n{art}\n{self._arrow_line(f'{STAR} {result_text}')}"

    def roll_dice(self, dice_str: str = "1d6") -> str:
        """Roll dice (e.g., 2d6, 1d20)."""
        try:
            if 'd' not in dice_str.lower():
                dice_str = f"1d{dice_str}"

            num, sides = dice_str.lower().split('d')
            num = int(num) if num else 1
            sides = int(sides)

            if num < 1 or sides < 1:
                return self._error("Dice values must be positive")
            if num > 20 or sides > 1000:
                return self._error("Max 20 dice with 1000 sides each")

            rolls = [random.randint(1, sides) for _ in range(num)]
            total = sum(rolls)

            dice_text = f"{B}{C.PURPLE}{num}d{sides}{R}"
            total_text = f"{B}{C.YELLOW}{total}{R}"

            if num == 1:
                return f"{self._header('Dice Roll')} {dice_text} {B}{COLOR_PRIMARY}{ARROW}{R} {total_text}"
            else:
                rolls_text = f"{COLOR_ACCENT}{rolls}{R}"
                return f"{self._header('Dice Roll')} {dice_text} {B}{COLOR_PRIMARY}{ARROW}{R} {rolls_text} {COLOR_PRIMARY}={R} {total_text}"

        except (ValueError, OverflowError):
            return self._error("Invalid dice format (use: 2d6, 1d20)")

    def eightball(self, question: str) -> str:
        """Magic 8-ball."""
        if not question.strip():
            return self._error("Ask me a question!")

        response = random.choice(self.eightball_responses)

        # Color based on response type
        if response in ["It is certain", "It is decidedly so", "Without a doubt", "Yes definitely", "You may rely on it"]:
            resp_color = COLOR_SUCCESS
        elif response in ["Don't count on it", "My reply is no", "My sources say no", "Outlook not so good", "Very doubtful"]:
            resp_color = COLOR_ERROR
        else:
            resp_color = COLOR_WARNING

        ball = (
            f"{C.PURPLE}  ___  {R}\n"
            f"{C.PURPLE} / {B}{C.PINK}8{R} {C.PURPLE}\\ {R}\n"
            f"{C.PURPLE} \\___/ {R}"
        )
        return f"{self._header('Magic 8-Ball')}\n{ball}\n{self._arrow_line(f'{B}{resp_color}{response}{R}')}"

    def rps(self, choice: str) -> str:
        """Rock Paper Scissors."""
        choices = ['rock', 'paper', 'scissors']
        choice = choice.lower().strip()

        aliases = {'r': 'rock', 'p': 'paper', 's': 'scissors'}
        choice = aliases.get(choice, choice)

        if choice not in choices:
            return self._error("Choose: rock, paper, or scissors (r/p/s)")

        bot_choice = random.choice(choices)

        # Emoji-style icons for choices
        icons = {'rock': '✊', 'paper': '✋', 'scissors': '✌'}

        if choice == bot_choice:
            result_color = COLOR_WARNING
            result = "DRAW"
            result_icon = DOT
        elif (choice == 'rock' and bot_choice == 'scissors') or \
             (choice == 'paper' and bot_choice == 'rock') or \
             (choice == 'scissors' and bot_choice == 'paper'):
            result_color = COLOR_SUCCESS
            result = "YOU WIN"
            result_icon = STAR
        else:
            result_color = COLOR_ERROR
            result = "YOU LOSE"
            result_icon = "✗"

        you_text = f"{B}{C.CYAN}{choice.upper()}{R} {icons[choice]}"
        bot_text = f"{B}{C.PINK}{bot_choice.upper()}{R} {icons[bot_choice]}"
        result_text = f"{B}{result_color}{result_icon} {result}{R}"
        return f"{self._header('Rock Paper Scissors')} {you_text} {COLOR_PRIMARY}vs{R} {bot_text} {B}{COLOR_PRIMARY}{ARROW}{R} {result_text}"

    def get_fact(self) -> str:
        """Get a random fun fact."""
        fact = random.choice(self.facts)
        return f"{self._header('Random Fact')}\n{self._arrow_line(f'{STAR} {COLOR_ACCENT}{fact}{R}')}"

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

            nick_text = f"{B}{C.PINK}{user['nick']}{R}"
            time_text = f"{C.YELLOW}{time_str}{R}"
            channel_text = f"{COLOR_ACCENT}{user['channel']}{R}"
            msg_text = f"{COLOR_VALUE}{user['message']}{R}"

            return (
                f"{self._header('User Seen')}\n"
                f"{self._arrow_line(f'{nick_text} {COLOR_PRIMARY}{DIVIDER*2}{R} {time_text} in {channel_text}')}\n"
                f"{self._arrow_line(f'{self._label('Message')}: {msg_text}')}"
            )
        else:
            return self._error(f"Haven't seen {nick} yet")

    def add_quote(self, quote: str, added_by: str) -> str:
        """Add a quote to the database."""
        self.quotes.append({
            'quote': quote,
            'added_by': added_by,
            'timestamp': time.time()
        })
        quote_num = len(self.quotes)
        return self._success(f"Quote {B}{C.YELLOW}#{quote_num}{R} added by {B}{C.CYAN}{added_by}{R}")

    def get_random_quote(self) -> str:
        """Get a random quote."""
        if not self.quotes:
            return self._error("No quotes stored yet. Use %addquote to add one.")

        quote_data = random.choice(self.quotes)
        quote_num = self.quotes.index(quote_data) + 1
        quote_text = f"{COLOR_ACCENT}{quote_data['quote']}{R}"
        by_text = f"{B}{C.PINK}{quote_data['added_by']}{R}"
        dq = '"'
        return (
            f"{self._header(f'Quote {B}{C.YELLOW}#{quote_num}{R}')}\n"
            f"{self._arrow_line(f'{C.YELLOW}{dq}{R}' + quote_text + f'{C.YELLOW}{dq}{R}')}\n"
            f"{self._arrow_line(f'{COLOR_PRIMARY}{DIVIDER*2}{R} added by {by_text}')}"
        )

    def get_uptime(self) -> str:
        """Get bot uptime."""
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
        return f"{self._header('Bot Uptime')} {B}{COLOR_SUCCESS}{uptime_str}{R}"

    def do_ping(self) -> str:
        """Return a pong with timestamp."""
        ts = time.strftime("%H:%M:%S", time.gmtime())
        return f"{self._header('Pong')} {B}{COLOR_SUCCESS}PONG!{R} {COLOR_ACCENT}{DOT}{R} {C.YELLOW}{ts}{R}"

    def hash_text(self, text: str) -> str:
        """Hash text with multiple algorithms."""
        md5 = hashlib.md5(text.encode()).hexdigest()
        sha1 = hashlib.sha1(text.encode()).hexdigest()
        sha256 = hashlib.sha256(text.encode()).hexdigest()
        sha256_short = sha256[:32] + "..."

        return (
            f"{self._header('Cryptographic Hash')}\n"
            f"{self._arrow_line(f'{self._label('MD5')}:    {C.LIGHT_BLUE}{md5}{R}')}\n"
            f"{self._arrow_line(f'{self._label('SHA1')}:   {C.CYAN}{sha1}{R}')}\n"
            f"{self._arrow_line(f'{self._label('SHA256')}: {C.LIGHT_CYAN}{sha256_short}{R}')}"
        )

    def do_base64(self, mode: str, text: str) -> str:
        """Encode or decode base64."""
        try:
            if mode in ('e', 'encode', 'enc'):
                result = base64.b64encode(text.encode()).decode()
                return f"{self._header('Base64 Encode')}\n{self._arrow_line(f'{COLOR_ACCENT}{result}{R}')}"
            elif mode in ('d', 'decode', 'dec'):
                result = base64.b64decode(text.encode()).decode('utf-8', errors='replace')
                result = Sanitizer.strip_irc_controls(result)[:300]
                return f"{self._header('Base64 Decode')}\n{self._arrow_line(f'{COLOR_ACCENT}{result}{R}')}"
            else:
                return self._error("Usage: %base64 <encode|decode> <text>")
        except Exception:
            return self._error("Invalid base64 input")

    def reverse_text(self, text: str) -> str:
        """Reverse a string."""
        reversed_text = text[::-1]
        return f"{self._header('Reverse Text')}\n{self._arrow_line(f'{COLOR_ACCENT}{reversed_text}{R}')}"

    def mock_text(self, text: str) -> str:
        """SpOnGeBoB mOcKiNg CaSe."""
        result = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(text)
        )
        return f"{self._header('Mock Text')}\n{self._arrow_line(f'{C.YELLOW}{result}{R}')}"

    def safe_calc(self, expr: str) -> str:
        """Safely evaluate a math expression."""
        if not re.match(r'^[\d\s+\-*/().,%^]+$', expr):
            return self._error("Invalid expression. Only numbers and +-*/()^. allowed")

        expr = expr.replace('^', '**')

        if len(expr) > 100:
            return self._error("Expression too long")

        if '**' in expr:
            parts = expr.split('**')
            for part in parts[1:]:
                num_match = re.match(r'\s*(\d+)', part)
                if num_match and int(num_match.group(1)) > 1000:
                    return self._error("Exponent too large (max 1000)")

        try:
            result = eval(expr, {"__builtins__": {}}, {})
            if isinstance(result, float):
                if abs(result) > 1e15 or (result != 0 and abs(result) < 1e-10):
                    result = f"{result:.6e}"
                else:
                    result = f"{result:.6f}".rstrip('0').rstrip('.')

            expr_text = f"{COLOR_ACCENT}{expr}{R}"
            result_text = f"{B}{C.YELLOW}{result}{R}"
            return f"{self._header('Calculator')} {expr_text} {COLOR_PRIMARY}={R} {result_text}"
        except ZeroDivisionError:
            return self._error("Division by zero")
        except Exception:
            return self._error("Could not evaluate expression")

    # ─── Command Handler ──────────────────────────────────────────

    def handle_command(self, channel: str, nick: str, message: str):
        """Handle bot commands."""
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
                self.send_message(channel, self._error(f"Usage: {p}weather <location>"))
                return
            location = Sanitizer.sanitize_location(" ".join(parts[1:]))
            if not location:
                self.send_message(channel, self._error("Invalid location"))
                return
            weather = self.get_weather(location)
            for line in weather.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.3)

        elif command in (f"{p}forecast", f"{p}f"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}forecast <location>"))
                return
            location = Sanitizer.sanitize_location(" ".join(parts[1:]))
            if not location:
                self.send_message(channel, self._error("Invalid location"))
                return
            forecasts = self.get_forecast(location, 3)
            for forecast in forecasts:
                self.send_message(channel, forecast)
                time.sleep(0.5)

        # ── Info ──
        elif command in (f"{p}urban", f"{p}ud"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}urban <term>"))
                return
            term = Sanitizer.sanitize_term(" ".join(parts[1:]))
            if not term:
                self.send_message(channel, self._error("Invalid search term"))
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
            result = self.coin_flip()
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command in (f"{p}roll", f"{p}dice"):
            dice_str = parts[1] if len(parts) > 1 else "1d6"
            if not re.match(r'^\d{0,3}d?\d{1,4}$', dice_str.lower()):
                self.send_message(channel, self._error("Invalid dice format (use: 2d6, 1d20)"))
                return
            result = self.roll_dice(dice_str)
            self.send_message(channel, result)

        elif command in (f"{p}8ball", f"{p}8"):
            question = " ".join(parts[1:])
            result = self.eightball(question)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command in (f"{p}rps",):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}rps <rock|paper|scissors>"))
                return
            result = self.rps(parts[1])
            self.send_message(channel, result)

        elif command == f"{p}fact":
            result = self.get_fact()
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.3)

        # ── Utility ──
        elif command == f"{p}seen":
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}seen <nick>"))
                return
            target_nick = Sanitizer.sanitize_nick(parts[1])
            if not target_nick:
                self.send_message(channel, self._error("Invalid nickname"))
                return
            result = self.get_seen(target_nick)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command == f"{p}addquote":
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}addquote <quote>"))
                return
            quote = Sanitizer.sanitize_quote(" ".join(parts[1:]))
            if not quote:
                self.send_message(channel, self._error("Invalid quote (too long or empty)"))
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
                self.send_message(channel, self._error(f"Usage: {p}calc <expression>"))
                return
            expr = " ".join(parts[1:])
            result = self.safe_calc(expr)
            self.send_message(channel, result)

        elif command == f"{p}hash":
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}hash <text>"))
                return
            text = Sanitizer.sanitize_generic(" ".join(parts[1:]))
            if not text:
                self.send_message(channel, self._error("Invalid input"))
                return
            result = self.hash_text(text)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command in (f"{p}base64", f"{p}b64"):
            if len(parts) < 3:
                self.send_message(channel, self._error(f"Usage: {p}base64 <encode|decode> <text>"))
                return
            mode = parts[1].lower()
            text = Sanitizer.sanitize_generic(" ".join(parts[2:]))
            if not text:
                self.send_message(channel, self._error("Invalid input"))
                return
            result = self.do_base64(mode, text)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command == f"{p}reverse":
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}reverse <text>"))
                return
            text = Sanitizer.sanitize_generic(" ".join(parts[1:]))
            if not text:
                self.send_message(channel, self._error("Invalid input"))
                return
            result = self.reverse_text(text)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command == f"{p}mock":
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}mock <text>"))
                return
            text = Sanitizer.sanitize_generic(" ".join(parts[1:]))
            if not text:
                self.send_message(channel, self._error("Invalid input"))
                return
            self.send_message(channel, self.mock_text(text))

        # ── Help ──
        elif command == f"{p}help":
            lines = [
                self._header(f"le0 Bot Commands {BOX_SEP} Help Menu"),
                f" {B}{C.CYAN}[Weather]{R}  {COLOR_ACCENT}{p}weather/w <loc>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}forecast/f <loc>{R}",
                f" {B}{C.YELLOW}[Info]{R}     {COLOR_ACCENT}{p}urban/ud <term>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}time [loc]{R}",
                f" {B}{C.PINK}[Fun]{R}      {COLOR_ACCENT}{p}coin/flip{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}roll/dice [XdY]{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}8ball/8 <q>{R}",
                f"             {COLOR_ACCENT}{p}rps <r/p/s>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}fact{R}",
                f" {B}{C.PURPLE}[Social]{R}   {COLOR_ACCENT}{p}quote{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}addquote <text>{R}",
                f" {B}{C.LIGHT_GREEN}[Utility]{R}  {COLOR_ACCENT}{p}seen <nick>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}ping{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}uptime{R}",
                f" {B}{C.ORANGE}[Tools]{R}    {COLOR_ACCENT}{p}calc <expr>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}hash <text>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}base64/b64 <e/d>{R}",
                f" {B}{C.LIGHT_BLUE}[Text]{R}     {COLOR_ACCENT}{p}reverse <text>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}mock <text>{R}",
                self._footer(f"Type {B}{COLOR_ACCENT}{p}help{R} anytime"),
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

    # Enhanced startup banner
    print(r"""
    ╔═══════════════════════════════════════╗
    ║     _       ___                       ║
    ║    | | ___ / _ \                      ║
    ║    | |/ _ \ | | |                     ║
    ║    | |  __/ |_| |                     ║
    ║    |_|\___|\___/                      ║
    ║                                       ║
    ║   ◆ IRC Bot v2.0 - Enhanced Theme    ║
    ╠═══════════════════════════════════════╣
    """)
    p = bot.command_prefix
    print(f"    ║  Weather  │ {p}weather/w  {p}forecast/f    ║")
    print(f"    ║  Info     │ {p}urban/ud   {p}time          ║")
    print(f"    ║  Fun      │ {p}coin  {p}roll  {p}8ball  {p}rps ║")
    print(f"    ║  Social   │ {p}quote  {p}addquote          ║")
    print(f"    ║  Utility  │ {p}seen  {p}ping  {p}uptime     ║")
    print(f"    ║  Tools    │ {p}calc  {p}hash  {p}base64     ║")
    print(f"    ║  Text     │ {p}reverse  {p}mock            ║")
    print(r"""    ╚═══════════════════════════════════════╝

    ▸ Ready! Press Ctrl+C to stop
    """)

    bot.run()
