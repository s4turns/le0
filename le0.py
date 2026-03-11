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
import os
import sys
import importlib
import fnmatch
import json
import secrets
import requests
from typing import Optional

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


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
BOX_SEP = "|"
ARROW  = ">"
BULLET = "*"
DIVIDER = "─"
STAR = "★"
DOT = "●"

# Color shortcuts for cleaner code
C = IRCColors
B  = IRCColors.BOLD
R  = IRCColors.RESET

# Theme color palette (no pink or purple)
COLOR_PRIMARY = IRCColors.CYAN
COLOR_ACCENT = IRCColors.LIGHT_CYAN
COLOR_SUCCESS = IRCColors.LIGHT_GREEN
COLOR_ERROR = IRCColors.RED
COLOR_WARNING = IRCColors.ORANGE
COLOR_INFO = IRCColors.YELLOW
COLOR_LABEL = IRCColors.CYAN
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

    # Valid hostname/IP pattern: labels, dots, colons (IPv6), brackets not needed
    HOSTNAME_RE = re.compile(r'^[A-Za-z0-9.\-:]{1,253}$')

    @staticmethod
    def sanitize_hostname(host: str) -> Optional[str]:
        """Sanitize a hostname or IP address."""
        host = Sanitizer.strip_irc_controls(host).strip().lower()
        if not host or len(host) > 253:
            return None
        if not Sanitizer.HOSTNAME_RE.match(host):
            return None
        return host

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
                 command_prefix: str = "%",
                 verify_ssl: bool = True,
                 nickserv_pass: Optional[str] = None,
                 sasl_username: Optional[str] = None,
                 sasl_password: Optional[str] = None,
                 admins: list = None):
        self.server = server
        self.port = port
        self.nickname = nickname
        self.channels = channels
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self.password = password
        self.command_prefix = command_prefix
        self.nickserv_pass = nickserv_pass
        self.sasl_username = sasl_username
        self.sasl_password = sasl_password
        self.admins = admins or []
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

        # Persistent data files (same directory as script)
        _base = os.path.dirname(os.path.abspath(__file__))
        self.quotes_file = os.path.join(_base, 'quotes.json')
        self.seen_file = os.path.join(_base, 'seen.json')
        self._last_seen_save = 0

        # Track last seen users
        self.seen_users = {}

        # Quote database
        self.quotes = []

        self._load_data()

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

        # Pending WHOIS requests: nick_lower -> {'channel': ch, 'data': {}}
        self.pending_whois = {}

        # Pending tells: nick_lower -> [(from_nick, message, ts), ...]
        self.tells = {}
        self.tells_file = os.path.join(_base, 'tells.json')
        self._load_tells()

        # PrivateBin instance
        self.privatebin_url = "https://paste.interdo.me"

    # ─── Enhanced formatting helpers ───────────────────────────────

    BOX_WIDTH = 90  # Fixed width for all boxes

    def _strip_irc_colors(self, text: str) -> str:
        """Strip IRC color codes to measure visible text length."""
        # Remove color codes (\x03XX or \x03XX,XX)
        text = re.sub(r'\x03\d{1,2}(,\d{1,2})?', '', text)
        # Remove formatting codes
        text = text.replace('\x02', '')  # Bold
        text = text.replace('\x1D', '')  # Italic
        text = text.replace('\x1F', '')  # Underline
        text = text.replace('\x0F', '')  # Reset
        return text

    def _truncate_visible(self, text: str, max_visible: int) -> str:
        """Truncate text to max visible chars, preserving IRC formatting codes."""
        visible = 0
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == '\x03':
                i += 1
                while i < len(text) and text[i].isdigit():
                    i += 1
                if i < len(text) and text[i] == ',':
                    i += 1
                    while i < len(text) and text[i].isdigit():
                        i += 1
            elif ch in '\x02\x1D\x1F\x0F':
                i += 1
            else:
                visible += 1
                if visible >= max_visible:
                    return text[:i + 1]
                i += 1
        return text

    def _header(self, text: str) -> str:
        """Bold accent title with no surrounding dashes."""
        clean = self._strip_irc_colors(text)
        return f"{B}{COLOR_ACCENT}{clean}{R}"

    def _footer(self, text: str = "") -> str:
        """Footer with bottom bracket rule."""
        if text:
            visible_len = len(self._strip_irc_colors(text))
            padding = self.BOX_WIDTH - visible_len - 2
            left_pad = padding // 2
            right_pad = padding - left_pad
            return f"{B}{COLOR_PRIMARY}{'-'*left_pad} {text} {'-'*right_pad}{R}"
        return f"{B}{COLOR_PRIMARY}{'-'*self.BOX_WIDTH}{R}"

    def _error(self, text: str) -> str:
        """Error message with icon."""
        return f"{B}{COLOR_ERROR}{BULLET}{R} {COLOR_ERROR}{text}{R}"

    def _success(self, text: str) -> str:
        """Success message with icon."""
        return f"{B}{COLOR_SUCCESS}{STAR}{R} {COLOR_SUCCESS}{text}{R}"

    def _info(self, text: str) -> str:
        """Info message with icon."""
        return f"{B}{COLOR_INFO}{DOT}{R} {COLOR_ACCENT}{text}{R}"

    def _wrap_text(self, text: str, max_width: int) -> list:
        """Wrap text to fit within max_width, preserving color codes."""
        lines = []
        current_line = ""
        current_visible = 0

        # Split into words but keep color codes attached
        i = 0
        while i < len(text):
            # Check for color codes
            if text[i:i+1] in ['\x03', '\x02', '\x1D', '\x1F', '\x0F']:
                # Add color code to current position
                if text[i] == '\x03':
                    # Color code format: \x03[NN][,NN]
                    end = i + 1
                    while end < len(text) and text[end].isdigit():
                        end += 1
                    if end < len(text) and text[end] == ',':
                        end += 1
                        while end < len(text) and text[end].isdigit():
                            end += 1
                    current_line += text[i:end]
                    i = end
                else:
                    current_line += text[i]
                    i += 1
            elif text[i] == ' ':
                if current_visible < max_width:
                    current_line += ' '
                    current_visible += 1
                    i += 1
                else:
                    lines.append(current_line)
                    current_line = ""
                    current_visible = 0
                    i += 1
            else:
                # Regular character
                if current_visible >= max_width:
                    lines.append(current_line)
                    current_line = ""
                    current_visible = 0
                current_line += text[i]
                current_visible += 1
                i += 1

        if current_line:
            lines.append(current_line)

        return lines if lines else [""]

    def _arrow_line(self, text: str) -> str:
        """Arrow-prefixed line."""
        max_content_width = self.BOX_WIDTH - 4  # 4 for " >  "
        visible_len = len(self._strip_irc_colors(text))

        if visible_len > max_content_width:
            text = self._truncate_visible(text, max_content_width - 3) + f"{R}..."

        return f" {B}{COLOR_ACCENT}{ARROW}{R} {text}"

    def _box_line(self, text: str) -> str:
        """Plain line (no arrow, no sides)."""
        max_content_width = self.BOX_WIDTH - 2
        visible_len = len(self._strip_irc_colors(text))

        if visible_len > max_content_width:
            text = self._truncate_visible(text, max_content_width - 3) + f"{R}..."

        return f" {text}"

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

    # ─── Persistence ──────────────────────────────────────────────

    def _load_data(self):
        """Load quotes and seen data from JSON files on startup."""
        try:
            if os.path.exists(self.quotes_file):
                with open(self.quotes_file, 'r') as f:
                    self.quotes = json.load(f)
                print(f"Loaded {len(self.quotes)} quotes from {self.quotes_file}")
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: could not load quotes: {e}")
            self.quotes = []

        try:
            if os.path.exists(self.seen_file):
                with open(self.seen_file, 'r') as f:
                    self.seen_users = json.load(f)
                print(f"Loaded {len(self.seen_users)} seen users from {self.seen_file}")
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: could not load seen data: {e}")
            self.seen_users = {}

    def _save_quotes(self):
        """Save quotes to JSON file."""
        try:
            with open(self.quotes_file, 'w') as f:
                json.dump(self.quotes, f, indent=2)
        except IOError as e:
            print(f"Warning: could not save quotes: {e}")

    def _save_seen(self):
        """Save seen data to JSON, at most once per 60 seconds."""
        now = time.time()
        if now - self._last_seen_save < 60:
            return
        self._last_seen_save = now
        try:
            with open(self.seen_file, 'w') as f:
                json.dump(self.seen_users, f, indent=2)
        except IOError as e:
            print(f"Warning: could not save seen data: {e}")

    def _load_tells(self):
        """Load pending tells from JSON file."""
        try:
            if os.path.exists(self.tells_file):
                with open(self.tells_file, 'r') as f:
                    self.tells = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: could not load tells: {e}")
            self.tells = {}

    def _save_tells(self):
        """Save pending tells to JSON file."""
        try:
            with open(self.tells_file, 'w') as f:
                json.dump(self.tells, f, indent=2)
        except IOError as e:
            print(f"Warning: could not save tells: {e}")

    # ─── Rate limiting ────────────────────────────────────────────

    def _check_rate_limit(self, nick: str) -> bool:
        """Check if a user is rate-limited. Returns True if allowed."""
        now = time.time()
        last = self.user_last_cmd.get(nick.lower(), 0)
        if now - last < self.rate_limit_seconds:
            return False
        self.user_last_cmd[nick.lower()] = now
        return True

    def _is_admin(self, hostmask: str) -> bool:
        """Check if a hostmask matches any configured admin pattern."""
        return any(fnmatch.fnmatch(hostmask.lower(), p.lower()) for p in self.admins)

    # ─── Connection ───────────────────────────────────────────────

    def connect(self):
        """Connect to the IRC server."""
        print(f"Connecting to {self.server}:{self.port}...")

        if self.use_ssl:
            if self.verify_ssl:
                context = ssl.create_default_context()
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.irc = context.wrap_socket(self.irc, server_hostname=self.server)

        self.irc.connect((self.server, self.port))

        if self.password:
            self.send_raw(f"PASS {self.password}")

        # SASL authentication
        if self.sasl_username and self.sasl_password:
            print("Requesting SASL authentication...")
            self.send_raw("CAP REQ :sasl")
            self.send_raw(f"NICK {self.nickname}")
            self.send_raw(f"USER {self.nickname} 0 * :{self.nickname}")

            # Wait for ACK and send credentials
            buf = ""
            while True:
                buf += self.irc.recv(2048).decode("UTF-8", errors="ignore")
                if "ACK :sasl" in buf or "ACK :sasl" in buf.lower():
                    break
                if "NAK" in buf:
                    print("SASL not supported by server, continuing without it")
                    self.send_raw("CAP END")
                    print("Connected!")
                    return

            self.send_raw("AUTHENTICATE PLAIN")

            buf = ""
            while True:
                buf += self.irc.recv(2048).decode("UTF-8", errors="ignore")
                if "AUTHENTICATE +" in buf:
                    break

            # SASL PLAIN: base64(\0username\0password)
            auth_string = f"\0{self.sasl_username}\0{self.sasl_password}"
            encoded = base64.b64encode(auth_string.encode()).decode()
            self.send_raw(f"AUTHENTICATE {encoded}")

            buf = ""
            while True:
                buf += self.irc.recv(2048).decode("UTF-8", errors="ignore")
                if " 903 " in buf:
                    print("SASL authentication successful!")
                    break
                if " 904 " in buf or " 905 " in buf:
                    print("SASL authentication failed!")
                    break

            self.send_raw("CAP END")
        else:
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
            feels_text = f"{B}{feels_color}{feels_c}°C{R} {COLOR_PRIMARY}/{R} {B}{feels_color}{feels_f}°F{R}"
            desc_text = f"{B}{C.YELLOW}{desc}{R}"

            # Apply color helpers to all weather data
            humidity_color = self._humidity_color(humidity)
            wind_color = self._wind_color(wind_speed)
            cloud_color = self._cloud_color(cloud_cover)

            line1 = self._header(f"Weather {BOX_SEP} {B}{COLOR_ACCENT}{location_display}{R}{COLOR_PRIMARY}")
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
            forecasts = [self._header(f"Forecast {BOX_SEP} {B}{COLOR_ACCENT}{location_display}{R}{COLOR_PRIMARY}")]

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
                        return f"{self._header('Time')}\n{self._arrow_line(f'{B}{C.YELLOW}{current_time}{R}')}"

                return self._error(f"Could not find location '{location}'")
            else:
                current_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                return f"{self._header('Time')}\n{self._arrow_line(f'{B}{C.YELLOW}{current_time}{R}')}"

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

                    # Word wrap the definition
                    max_line_width = self.BOX_WIDTH - 6  # Space for "║ > text ║"
                    words = meaning.split()
                    lines = []
                    current_line = ""

                    for w in words:
                        if len(current_line) + len(w) + 1 <= max_line_width:
                            current_line += (w + " ")
                        else:
                            if current_line:
                                lines.append(current_line.rstrip())
                            current_line = w + " "

                    if current_line:
                        lines.append(current_line.rstrip())

                    # Build output with word and definition on separate lines
                    word_text = f"{B}{C.CYAN}{word}{R}"
                    output = f"{self._header('Urban Dictionary')}\n"
                    output += f"{self._arrow_line(word_text)}\n"

                    for line in lines[:5]:  # Max 5 lines of definition
                        output += f"{self._arrow_line(f'{COLOR_ACCENT}{line}{R}')}\n"

                    return output
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
        letter = 'H' if result == 'HEADS' else 'T'

        line1 = f"{coin_color}  _____  {R}"
        line2 = f"{coin_color} /     \\ {R}"
        line3 = f"{coin_color}|   {B}{letter}{R}{coin_color}   |{R}"
        line4 = f"{coin_color} \\_____/ {R}"

        art = (
            f"{self._box_line(line1)}\n"
            f"{self._box_line(line2)}\n"
            f"{self._box_line(line3)}\n"
            f"{self._box_line(line4)}"
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

            dice_text = f"{B}{C.YELLOW}{num}d{sides}{R}"
            total_text = f"{B}{C.YELLOW}{total}{R}"

            if num == 1:
                return f"{self._header('Dice Roll')}\n{self._arrow_line(f'{dice_text} {B}{COLOR_PRIMARY}>{R} {total_text}')}"
            else:
                rolls_text = f"{COLOR_ACCENT}{rolls}{R}"
                return f"{self._header('Dice Roll')}\n{self._arrow_line(f'{dice_text} {B}{COLOR_PRIMARY}>{R} {rolls_text} {COLOR_PRIMARY}={R} {total_text}')}"

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

        line1 = f"{C.YELLOW}  ___  {R}"
        line2 = f"{C.YELLOW} / {B}{C.CYAN}8{R} {C.YELLOW}\\ {R}"
        line3 = f"{C.YELLOW} \\___/ {R}"

        ball = (
            f"{self._box_line(line1)}\n"
            f"{self._box_line(line2)}\n"
            f"{self._box_line(line3)}"
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

        if choice == bot_choice:
            result_color = COLOR_WARNING
            result = "DRAW"
        elif (choice == 'rock' and bot_choice == 'scissors') or \
             (choice == 'paper' and bot_choice == 'rock') or \
             (choice == 'scissors' and bot_choice == 'paper'):
            result_color = COLOR_SUCCESS
            result = "YOU WIN"
        else:
            result_color = COLOR_ERROR
            result = "YOU LOSE"

        you_text = f"{B}{C.CYAN}{choice.upper()}{R}"
        bot_text = f"{B}{C.CYAN}{bot_choice.upper()}{R}"
        result_text = f"{B}{result_color}{result}{R}"

        return (
            f"{self._header('Rock Paper Scissors')}\n"
            f"{self._arrow_line(f'You: {you_text} vs Bot: {bot_text}')}\n"
            f"{self._arrow_line(f'Result: {result_text}')}"
        )

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
        self._save_seen()

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

            nick_text = f"{B}{C.CYAN}{user['nick']}{R}"
            time_text = f"{C.YELLOW}{time_str}{R}"
            channel_text = f"{COLOR_ACCENT}{user['channel']}{R}"
            msg_text = f"{COLOR_VALUE}{user['message']}{R}"

            msg_label = self._label('Message')
            return (
                f"{self._header('User Seen')}\n"
                f"{self._arrow_line(f'{nick_text} {COLOR_PRIMARY}{DIVIDER*2}{R} {time_text} in {channel_text}')}\n"
                f"{self._arrow_line(f'{msg_label}: {msg_text}')}"
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
        self._save_quotes()
        quote_num = len(self.quotes)
        return self._success(f"Quote {B}{C.YELLOW}#{quote_num}{R} added by {B}{C.CYAN}{added_by}{R}")

    def get_random_quote(self) -> str:
        """Get a random quote."""
        if not self.quotes:
            return self._error("No quotes stored yet. Use %addquote to add one.")

        quote_data = random.choice(self.quotes)
        quote_num = self.quotes.index(quote_data) + 1
        quote_text = f"{COLOR_ACCENT}{quote_data['quote']}{R}"
        by_text = f"{B}{C.CYAN}{quote_data['added_by']}{R}"
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
        return f"{self._header('Bot Uptime')}\n{self._arrow_line(f'{B}{COLOR_SUCCESS}{uptime_str}{R}')}"

    def do_ping(self) -> str:
        """Return a pong with timestamp."""
        ts = time.strftime("%H:%M:%S", time.gmtime())
        return f"{self._header('Pong')}\n{self._arrow_line(f'{B}{COLOR_SUCCESS}PONG!{R} {COLOR_ACCENT}{DOT}{R} {C.YELLOW}{ts}{R}')}"

    def hash_text(self, text: str) -> str:
        """Hash text with multiple algorithms."""
        md5 = hashlib.md5(text.encode()).hexdigest()
        sha1 = hashlib.sha1(text.encode()).hexdigest()
        sha256 = hashlib.sha256(text.encode()).hexdigest()
        sha256_short = sha256[:32] + "..."

        md5_label = self._label('MD5')
        sha1_label = self._label('SHA1')
        sha256_label = self._label('SHA256')

        return (
            f"{self._header('Cryptographic Hash')}\n"
            f"{self._arrow_line(f'{md5_label}:    {C.LIGHT_BLUE}{md5}{R}')}\n"
            f"{self._arrow_line(f'{sha1_label}:   {C.CYAN}{sha1}{R}')}\n"
            f"{self._arrow_line(f'{sha256_label}: {C.LIGHT_CYAN}{sha256_short}{R}')}"
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
            return f"{self._header('Calculator')}\n{self._arrow_line(f'{expr_text} {COLOR_PRIMARY}={R} {result_text}')}"
        except ZeroDivisionError:
            return self._error("Division by zero")
        except Exception:
            return self._error("Could not evaluate expression")

    def http_status_info(self, code: int) -> Optional[str]:
        """Return RFC description for an HTTP status code, or None if unknown."""
        codes = {
            100: ("Continue",                        "Keep sending the request body.",                         "RFC 9110 §15.2.1"),
            101: ("Switching Protocols",             "Server is switching to requested protocol.",             "RFC 9110 §15.2.2"),
            102: ("Processing",                      "Request received, still processing.",                   "RFC 2518 §10.1"),
            103: ("Early Hints",                     "Preload resources while server prepares response.",      "RFC 8297"),
            200: ("OK",                              "Request succeeded.",                                     "RFC 9110 §15.3.1"),
            201: ("Created",                         "Resource successfully created.",                         "RFC 9110 §15.3.2"),
            202: ("Accepted",                        "Request accepted but not yet processed.",                "RFC 9110 §15.3.3"),
            203: ("Non-Authoritative Information",   "Response from a third-party, not the origin server.",   "RFC 9110 §15.3.4"),
            204: ("No Content",                      "Success, but no body to return.",                       "RFC 9110 §15.3.5"),
            205: ("Reset Content",                   "Success; client should reset the document view.",       "RFC 9110 §15.3.6"),
            206: ("Partial Content",                 "Partial resource returned (range request).",            "RFC 9110 §15.3.7"),
            207: ("Multi-Status",                    "Multiple status codes for multiple operations.",        "RFC 4918 §11.1"),
            208: ("Already Reported",                "Members already listed in a previous reply.",           "RFC 5842 §7.1"),
            226: ("IM Used",                         "Response is a delta from a prior version.",             "RFC 3229 §10.4.1"),
            300: ("Multiple Choices",                "Multiple representations available; pick one.",         "RFC 9110 §15.4.1"),
            301: ("Moved Permanently",               "Resource has a new permanent URL.",                     "RFC 9110 §15.4.2"),
            302: ("Found",                           "Resource temporarily at a different URL.",              "RFC 9110 §15.4.3"),
            303: ("See Other",                       "Use GET on the redirect URL.",                          "RFC 9110 §15.4.4"),
            304: ("Not Modified",                    "Cached version is still valid; use it.",                "RFC 9110 §15.4.5"),
            305: ("Use Proxy",                       "Must access resource through proxy. (Deprecated)",      "RFC 9110 §15.4.6"),
            307: ("Temporary Redirect",              "Same as 302 but method must not change.",               "RFC 9110 §15.4.8"),
            308: ("Permanent Redirect",              "Same as 301 but method must not change.",               "RFC 9110 §15.4.9"),
            400: ("Bad Request",                     "Server couldn't understand the request.",               "RFC 9110 §15.5.1"),
            401: ("Unauthorized",                    "Authentication required.",                              "RFC 9110 §15.5.2"),
            402: ("Payment Required",                "Reserved for future use.",                              "RFC 9110 §15.5.3"),
            403: ("Forbidden",                       "Server understood but refuses to authorize.",           "RFC 9110 §15.5.4"),
            404: ("Not Found",                       "Resource doesn't exist.",                               "RFC 9110 §15.5.5"),
            405: ("Method Not Allowed",              "HTTP method not supported for this resource.",          "RFC 9110 §15.5.6"),
            406: ("Not Acceptable",                  "No content matching the client's Accept headers.",      "RFC 9110 §15.5.7"),
            407: ("Proxy Authentication Required",   "Must authenticate with proxy first.",                   "RFC 9110 §15.5.8"),
            408: ("Request Timeout",                 "Server timed out waiting for the request.",             "RFC 9110 §15.5.9"),
            409: ("Conflict",                        "Request conflicts with current state of resource.",     "RFC 9110 §15.5.10"),
            410: ("Gone",                            "Resource permanently removed with no forwarding.",      "RFC 9110 §15.5.11"),
            411: ("Length Required",                 "Content-Length header required.",                       "RFC 9110 §15.5.12"),
            412: ("Precondition Failed",             "A request condition evaluated to false.",               "RFC 9110 §15.5.13"),
            413: ("Content Too Large",               "Request body exceeds server's limit.",                  "RFC 9110 §15.5.14"),
            414: ("URI Too Long",                    "Request URI is too long to process.",                   "RFC 9110 §15.5.15"),
            415: ("Unsupported Media Type",          "Server won't accept the request's media format.",      "RFC 9110 §15.5.16"),
            416: ("Range Not Satisfiable",           "Requested range can't be fulfilled.",                   "RFC 9110 §15.5.17"),
            417: ("Expectation Failed",              "Expect header can't be met.",                           "RFC 9110 §15.5.18"),
            418: ("I'm a Teapot",                    "Refuses to brew coffee. It's a teapot.",                "RFC 9110 §15.5.19"),
            421: ("Misdirected Request",             "Request sent to a server that can't produce a response.","RFC 9110 §15.5.20"),
            422: ("Unprocessable Content",           "Well-formed but semantically invalid request.",         "RFC 9110 §15.5.21"),
            423: ("Locked",                          "Resource is locked.",                                   "RFC 4918 §11.3"),
            424: ("Failed Dependency",               "Request failed because a dependency failed.",           "RFC 4918 §11.4"),
            425: ("Too Early",                       "Server won't risk processing a replayed request.",      "RFC 8470 §5.2"),
            426: ("Upgrade Required",                "Client must upgrade to a different protocol.",          "RFC 9110 §15.5.22"),
            428: ("Precondition Required",           "Request must be conditional to prevent lost updates.",  "RFC 6585 §3"),
            429: ("Too Many Requests",               "Rate limit hit; slow down.",                            "RFC 6585 §4"),
            431: ("Request Header Fields Too Large", "Headers too large to process.",                         "RFC 6585 §5"),
            451: ("Unavailable For Legal Reasons",   "Resource blocked for legal reasons.",                   "RFC 7725 §3"),
            500: ("Internal Server Error",           "Server crashed or hit an unexpected condition.",        "RFC 9110 §15.6.1"),
            501: ("Not Implemented",                 "Server doesn't support the requested method.",          "RFC 9110 §15.6.2"),
            502: ("Bad Gateway",                     "Upstream server sent an invalid response.",             "RFC 9110 §15.6.3"),
            503: ("Service Unavailable",             "Server is down or overloaded. Try again later.",        "RFC 9110 §15.6.4"),
            504: ("Gateway Timeout",                 "Upstream server didn't respond in time.",               "RFC 9110 §15.6.5"),
            505: ("HTTP Version Not Supported",      "Server doesn't support the HTTP version used.",         "RFC 9110 §15.6.6"),
            506: ("Variant Also Negotiates",         "Circular reference in content negotiation config.",     "RFC 2295 §8.1"),
            507: ("Insufficient Storage",            "Server has no space to complete the request.",          "RFC 4918 §11.5"),
            508: ("Loop Detected",                   "Infinite loop detected while processing request.",      "RFC 5842 §7.2"),
            510: ("Not Extended",                    "Further extensions required for the server to fulfill.","RFC 2774 §7"),
            511: ("Network Authentication Required", "Must authenticate to gain network access.",             "RFC 6585 §6"),
        }
        if code not in codes:
            return None
        name, desc, rfc = codes[code]
        return f"{B}{C.CYAN}{code}{R} {B}{COLOR_ACCENT}{name}{R} {COLOR_PRIMARY}|{R} {desc} {COLOR_PRIMARY}[{rfc}]{R}"

    # ─── Title / Define / Wiki / Translate / Shorten / Stock / IsUp / Paste / Tell ─

    def get_title(self, url: str) -> str:
        """Fetch the <title> of a webpage."""
        try:
            resp = requests.get(url, timeout=6, headers={'User-Agent': 'le0-irc-bot/1.0'}, allow_redirects=True)
            resp.raise_for_status()
            # Extract title with regex (avoids html.parser encoding edge-cases)
            m = re.search(r'<title[^>]*>([^<]{1,300})', resp.text, re.IGNORECASE | re.DOTALL)
            if not m:
                return self._error("No title found")
            title = re.sub(r'\s+', ' ', m.group(1)).strip()
            # Decode HTML entities
            for ent, ch in [('&amp;','&'),('&lt;','<'),('&gt;','>'),('&quot;','"'),('&#39;',"'"),('&nbsp;',' ')]:
                title = title.replace(ent, ch)
            return f"{self._header('Title')} {COLOR_ACCENT}{title}{R}"
        except Exception as e:
            return self._error(f"Could not fetch title: {e}")

    def get_definition(self, word: str) -> str:
        """Look up a word definition via Free Dictionary API."""
        try:
            url = f"https://api.dictionaryapi.dev/api/v2/entries/en/{urllib.parse.quote(word)}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 404:
                return self._error(f"No definition found for '{word}'")
            data = resp.json()
            entry = data[0]
            phonetic = entry.get('phonetic', '')
            meanings = entry.get('meanings', [])
            lines = [self._header(f"Define: {word}" + (f"  {phonetic}" if phonetic else ""))]
            shown = 0
            for meaning in meanings[:3]:
                if shown >= 3:
                    break
                pos = meaning.get('partOfSpeech', '')
                for defn in meaning.get('definitions', [])[:1]:
                    definition = defn.get('definition', '')
                    example = defn.get('example', '')
                    lines.append(self._arrow_line(f"{B}{C.CYAN}{pos}{R} {COLOR_ACCENT}{definition}{R}"))
                    if example:
                        lines.append(self._arrow_line(f"  {C.LIGHT_GREY}\"{example}\"{R}"))
                    shown += 1
            return "\n".join(lines)
        except Exception as e:
            return self._error(f"Definition lookup failed: {e}")

    def get_wiki(self, topic: str) -> str:
        """Fetch a Wikipedia article summary."""
        try:
            url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(topic)}"
            resp = requests.get(url, timeout=5, headers={'Accept': 'application/json'})
            if resp.status_code == 404:
                return self._error(f"No Wikipedia article found for '{topic}'")
            data = resp.json()
            if data.get('type') == 'disambiguation':
                return self._error(f"'{topic}' is a disambiguation page — be more specific")
            title = data.get('title', topic)
            extract = data.get('extract', '')
            # Trim to first 2 sentences max
            sentences = re.split(r'(?<=[.!?])\s+', extract)
            summary = ' '.join(sentences[:2])
            if len(summary) > 400:
                summary = summary[:397] + '...'
            wiki_url = data.get('content_urls', {}).get('desktop', {}).get('page', '')
            lines = [self._header(f"Wiki: {title}")]
            lines.append(self._arrow_line(f"{COLOR_ACCENT}{summary}{R}"))
            if wiki_url:
                lines.append(self._arrow_line(f"{C.LIGHT_GREY}{wiki_url}{R}"))
            return "\n".join(lines)
        except Exception as e:
            return self._error(f"Wikipedia lookup failed: {e}")

    def get_translate(self, text: str, target: str) -> str:
        """Translate text using MyMemory API (auto-detect source)."""
        try:
            params = urllib.parse.urlencode({'q': text, 'langpair': f'autodetect|{target}'})
            url = f"https://api.mymemory.translated.net/get?{params}"
            resp = requests.get(url, timeout=6)
            data = resp.json()
            if data.get('responseStatus') != 200:
                return self._error(data.get('responseDetails', 'Translation failed'))
            translated = data['responseData']['translatedText']
            detected = data.get('responseData', {}).get('detectedLanguage', '')
            label = f"Translate → {target.upper()}"
            if detected:
                label += f" (from {detected})"
            lines = [
                self._header(label),
                self._arrow_line(f"{COLOR_ACCENT}{translated}{R}"),
            ]
            return "\n".join(lines)
        except Exception as e:
            return self._error(f"Translation failed: {e}")

    def get_shorten(self, url: str) -> str:
        """Shorten a URL using TinyURL."""
        try:
            api = f"https://tinyurl.com/api-create.php?url={urllib.parse.quote(url, safe='')}"
            resp = requests.get(api, timeout=5)
            short = resp.text.strip()
            if not short.startswith('http'):
                return self._error("Shortener returned an unexpected response")
            return f"{self._header('Shorten')} {COLOR_ACCENT}{short}{R}"
        except Exception as e:
            return self._error(f"URL shortening failed: {e}")

    def get_stock(self, ticker: str) -> str:
        """Get stock quote from Yahoo Finance."""
        try:
            ticker = ticker.upper()
            url = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(ticker)}?interval=1d&range=1d"
            resp = requests.get(url, timeout=6, headers={'User-Agent': 'le0-irc-bot/1.0'})
            data = resp.json()
            meta = data.get('chart', {}).get('result', [{}])[0].get('meta', {})
            if not meta:
                return self._error(f"No data found for ticker '{ticker}'")
            name        = meta.get('shortName', ticker)
            price       = meta.get('regularMarketPrice', 0)
            prev_close  = meta.get('chartPreviousClose', meta.get('previousClose', 0))
            currency    = meta.get('currency', 'USD')
            exchange    = meta.get('exchangeName', '')
            change      = price - prev_close if prev_close else 0
            change_pct  = (change / prev_close * 100) if prev_close else 0
            if change >= 0:
                arrow = f"{C.LIGHT_GREEN}▲{R}"
                change_col = C.LIGHT_GREEN
            else:
                arrow = f"{C.RED}▼{R}"
                change_col = C.RED
            lines = [
                self._header(f"Stock: {ticker} — {name}"),
                self._arrow_line(
                    f"{B}{C.CYAN}Price{R}  {COLOR_PRIMARY}|{R} {B}{COLOR_ACCENT}{price:.2f} {currency}{R}"
                    f"  {arrow} {change_col}{change:+.2f} ({change_pct:+.2f}%){R}"
                    + (f"  {C.LIGHT_GREY}{exchange}{R}" if exchange else "")
                ),
            ]
            return "\n".join(lines)
        except Exception as e:
            return self._error(f"Stock lookup failed: {e}")

    def get_isup(self, host: str) -> str:
        """Check if a host/URL is reachable."""
        # Normalize: strip scheme if present
        original = host
        if '://' not in host:
            host = 'http://' + host
        try:
            resp = requests.get(host, timeout=5, headers={'User-Agent': 'le0-irc-bot/1.0'}, allow_redirects=True)
            code = resp.status_code
            if code < 400:
                status = f"{C.LIGHT_GREEN}UP{R}"
            else:
                status = f"{C.ORANGE}UP (HTTP {code}){R}"
            return f"{self._header('IsUp')} {B}{COLOR_ACCENT}{original}{R} is {status}"
        except requests.exceptions.ConnectionError:
            return f"{self._header('IsUp')} {B}{COLOR_ACCENT}{original}{R} is {C.RED}DOWN{R} (connection refused)"
        except requests.exceptions.Timeout:
            return f"{self._header('IsUp')} {B}{COLOR_ACCENT}{original}{R} is {C.RED}DOWN{R} (timed out)"
        except Exception as e:
            return self._error(f"IsUp check failed: {e}")

    @staticmethod
    def _base58_encode(data: bytes) -> str:
        """Encode bytes to Base58 (Bitcoin alphabet)."""
        ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        count = 0
        for byte in data:
            if byte == 0:
                count += 1
            else:
                break
        n = int.from_bytes(data, 'big')
        result = []
        while n > 0:
            n, r = divmod(n, 58)
            result.append(ALPHABET[r])
        result.extend(['1'] * count)
        return ''.join(reversed(result))

    def create_paste(self, text: str, expire: str = '1week') -> str:
        """Create a PrivateBin paste and return the URL."""
        if not _CRYPTO_AVAILABLE:
            return self._error("PrivateBin paste requires the 'cryptography' package")
        try:
            import zlib as _zlib
            key  = secrets.token_bytes(32)
            iv   = secrets.token_bytes(12)
            salt = secrets.token_bytes(8)

            kdf = PBKDF2HMAC(
                algorithm=crypto_hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=310000,
            )
            aes_key = kdf.derive(key)

            compressed = _zlib.compress(text.encode('utf-8'), level=6)

            spec = [
                base64.b64encode(iv).decode(),
                base64.b64encode(salt).decode(),
                310000, 256, 128, 'aes', 'gcm', 'zlib'
            ]
            adata = [spec, 'plaintext', 0, 0]
            additional = json.dumps(adata, separators=(',', ':')).encode('utf-8')

            aesgcm = AESGCM(aes_key)
            ct_tag = aesgcm.encrypt(iv, compressed, additional)

            payload = {
                'v': 2,
                'ct': base64.b64encode(ct_tag).decode(),
                'adata': adata,
                'meta': {'expire': expire}
            }
            resp = requests.post(
                self.privatebin_url,
                json=payload,
                headers={
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'JSONHttpRequest',
                },
                timeout=8,
            )
            data = resp.json()
            if data.get('status') != 0:
                return self._error(data.get('message', 'Paste creation failed'))
            paste_id = data['id']
            key_b58 = self._base58_encode(key)
            url = f"{self.privatebin_url}/?{paste_id}#{key_b58}"
            return f"{self._header('Paste')} {COLOR_ACCENT}{url}{R}"
        except Exception as e:
            return self._error(f"Paste failed: {e}")

    def add_tell(self, from_nick: str, to_nick: str, message: str) -> str:
        """Store a tell message for delivery when to_nick next speaks."""
        key = to_nick.lower()
        if key not in self.tells:
            self.tells[key] = []
        # Limit 5 pending tells per target
        if len(self.tells[key]) >= 5:
            return self._error(f"Too many pending tells for {to_nick} (max 5)")
        self.tells[key].append({
            'from': from_nick,
            'message': message,
            'ts': int(time.time()),
        })
        self._save_tells()
        return f"{self._header('Tell')} {COLOR_ACCENT}Message queued for {to_nick}.{R}"

    def deliver_tells(self, nick: str, channel: str):
        """Deliver any pending tells to nick in channel."""
        key = nick.lower()
        pending = self.tells.pop(key, None)
        if not pending:
            return
        self._save_tells()
        for tell in pending:
            from_nick = tell['from']
            message   = tell['message']
            ts        = tell['ts']
            ago       = int(time.time()) - ts
            if ago < 60:
                when = f"{ago}s ago"
            elif ago < 3600:
                when = f"{ago//60}m ago"
            elif ago < 86400:
                when = f"{ago//3600}h ago"
            else:
                when = f"{ago//86400}d ago"
            self.send_message(channel,
                f"{B}{C.CYAN}{nick}{R}: {COLOR_ACCENT}[tell from {from_nick}, {when}]{R} {message}")
            time.sleep(0.4)

    # ─── DNS / GeoIP ──────────────────────────────────────────────

    def get_dns(self, hostname: str) -> str:
        """Look up A and AAAA records for a hostname."""
        results_a = []
        results_aaaa = []

        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
            seen = set()
            for info in infos:
                ip = info[4][0]
                if ip not in seen:
                    results_a.append(ip)
                    seen.add(ip)
        except socket.gaierror:
            pass

        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            seen = set()
            for info in infos:
                ip = info[4][0]
                if ip not in seen:
                    results_aaaa.append(ip)
                    seen.add(ip)
        except socket.gaierror:
            pass

        if not results_a and not results_aaaa:
            return self._error(f"No DNS records found for {hostname}")

        lines = [self._header(f"DNS: {hostname}")]
        for ip in results_a:
            lines.append(self._arrow_line(f"{B}{C.CYAN}A   {R} {COLOR_ACCENT}{ip}{R}"))
        for ip in results_aaaa:
            lines.append(self._arrow_line(f"{B}{C.YELLOW}AAAA{R} {COLOR_ACCENT}{ip}{R}"))
        return "\n".join(lines)

    def get_geo(self, query: str) -> str:
        """Get geolocation info for an IP address or hostname."""
        try:
            url = f"http://ip-api.com/json/{urllib.parse.quote(query)}?fields=status,message,country,regionName,city,isp,as,query,lat,lon,timezone"
            resp = requests.get(url, timeout=5)
            data = resp.json()

            if data.get('status') != 'success':
                return self._error(data.get('message', 'Lookup failed'))

            ip      = data.get('query', query)
            city    = data.get('city', '?')
            region  = data.get('regionName', '?')
            country = data.get('country', '?')
            isp     = data.get('isp', '?')
            asn     = data.get('as', '?')
            tz      = data.get('timezone', '?')
            lat     = data.get('lat', '')
            lon     = data.get('lon', '')

            lines = [
                self._header(f"GeoIP: {ip}"),
                self._arrow_line(f"{B}{C.CYAN}Location{R} {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{city}, {region}, {country}{R}"),
                self._arrow_line(f"{B}{C.YELLOW}ISP{R}      {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{isp}{R}"),
                self._arrow_line(f"{B}{C.LIGHT_GREEN}ASN{R}      {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{asn}{R}"),
                self._arrow_line(f"{B}{C.ORANGE}Timezone{R} {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{tz}{R}"),
            ]
            if lat and lon:
                lines.append(self._arrow_line(f"{B}{C.LIGHT_BLUE}Coords{R}   {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{lat}, {lon}{R}"))
            return "\n".join(lines)
        except Exception as e:
            return self._error(f"GeoIP lookup failed: {e}")

    # ─── Command Handler ──────────────────────────────────────────

    def handle_command(self, channel: str, nick: str, hostmask: str, message: str):
        """Handle bot commands."""
        parts = message.strip().split()
        if not parts:
            return

        command = parts[0].lower()
        p = self.command_prefix

        # ── Admin (bypasses rate limit) ──
        if self._is_admin(hostmask):
            if command == f"{p}join":
                if len(parts) < 2:
                    self.send_message(channel, self._error(f"Usage: {p}join <channel>"))
                    return
                target = Sanitizer.sanitize_irc_output(parts[1])
                self.send_raw(f"JOIN {target}")
                return

            elif command == f"{p}part":
                target = Sanitizer.sanitize_irc_output(parts[1]) if len(parts) > 1 else channel
                self.send_raw(f"PART {target}")
                return

            elif command == f"{p}quit":
                msg = Sanitizer.sanitize_irc_output(" ".join(parts[1:])) if len(parts) > 1 else "bye"
                self.send_raw(f"QUIT :{msg}")
                return

            elif command == f"{p}say":
                if len(parts) < 3:
                    self.send_message(channel, self._error(f"Usage: {p}say <channel> <message>"))
                    return
                target = Sanitizer.sanitize_irc_output(parts[1])
                msg = Sanitizer.sanitize_irc_output(" ".join(parts[2:]))
                self.send_message(target, msg)
                return

            elif command == f"{p}nick":
                if len(parts) < 2:
                    self.send_message(channel, self._error(f"Usage: {p}nick <newnick>"))
                    return
                new_nick = Sanitizer.sanitize_nick(parts[1])
                if not new_nick:
                    self.send_message(channel, self._error("Invalid nickname"))
                    return
                self.send_raw(f"NICK {new_nick}")
                return

            elif command == f"{p}kick":
                if len(parts) < 2:
                    self.send_message(channel, self._error(f"Usage: {p}kick <nick> [reason]"))
                    return
                target_nick = Sanitizer.sanitize_nick(parts[1])
                if not target_nick:
                    self.send_message(channel, self._error("Invalid nickname"))
                    return
                reason = Sanitizer.sanitize_irc_output(" ".join(parts[2:])) if len(parts) > 2 else "."
                self.send_raw(f"KICK {channel} {target_nick} :{reason}")
                return

            elif command == f"{p}raw":
                if len(parts) < 2:
                    self.send_message(channel, self._error(f"Usage: {p}raw <command>"))
                    return
                raw_cmd = Sanitizer.sanitize_irc_output(" ".join(parts[1:]))
                self.send_raw(raw_cmd)
                return

        if not self._check_rate_limit(nick):
            return

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
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

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
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

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
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

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
            result = self.get_uptime()
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command == f"{p}ping":
            result = self.do_ping()
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        elif command == f"{p}calc":
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}calc <expression>"))
                return
            expr = " ".join(parts[1:])
            result = self.safe_calc(expr)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

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
            result = self.mock_text(text)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        # ── Title ──
        elif command in (f"{p}title", f"{p}t"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}title <url>"))
                return
            url_arg = Sanitizer.sanitize_irc_output(parts[1])
            result = self.get_title(url_arg)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        # ── Define ──
        elif command in (f"{p}define", f"{p}def"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}define <word>"))
                return
            word = Sanitizer.sanitize_term(parts[1])
            if not word:
                self.send_message(channel, self._error("Invalid word"))
                return
            result = self.get_definition(word)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.3)

        # ── Wikipedia ──
        elif command in (f"{p}wiki", f"{p}wi"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}wiki <topic>"))
                return
            topic = Sanitizer.sanitize_term(" ".join(parts[1:]))
            if not topic:
                self.send_message(channel, self._error("Invalid topic"))
                return
            result = self.get_wiki(topic)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.3)

        # ── Translate ──
        elif command in (f"{p}tr", f"{p}translate"):
            if len(parts) < 3:
                self.send_message(channel, self._error(f"Usage: {p}tr <lang> <text>"))
                return
            lang = Sanitizer.sanitize_term(parts[1])
            text_arg = Sanitizer.sanitize_term(" ".join(parts[2:]))
            if not lang or not text_arg:
                self.send_message(channel, self._error("Invalid language or text"))
                return
            result = self.get_translate(text_arg, lang)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        # ── Shorten ──
        elif command in (f"{p}shorten", f"{p}short"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}shorten <url>"))
                return
            url_arg = Sanitizer.sanitize_irc_output(parts[1])
            result = self.get_shorten(url_arg)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        # ── Stock ──
        elif command in (f"{p}stock", f"{p}stocks"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}stock <ticker>"))
                return
            ticker = Sanitizer.sanitize_term(parts[1])
            if not ticker:
                self.send_message(channel, self._error("Invalid ticker"))
                return
            result = self.get_stock(ticker)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        # ── IsUp ──
        elif command in (f"{p}isup", f"{p}up"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}isup <host|url>"))
                return
            host_arg = Sanitizer.sanitize_irc_output(parts[1])
            result = self.get_isup(host_arg)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        # ── Paste ──
        elif command == f"{p}paste":
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}paste <text>"))
                return
            paste_text = Sanitizer.sanitize_generic(" ".join(parts[1:]))
            if not paste_text:
                self.send_message(channel, self._error("Invalid or empty paste content"))
                return
            result = self.create_paste(paste_text)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        # ── Tell ──
        elif command in (f"{p}tell", f"{p}remind"):
            if len(parts) < 3:
                self.send_message(channel, self._error(f"Usage: {p}tell <nick> <message>"))
                return
            to_nick = Sanitizer.sanitize_nick(parts[1])
            msg_text = Sanitizer.sanitize_quote(" ".join(parts[2:]))
            if not to_nick or not msg_text:
                self.send_message(channel, self._error("Invalid nick or message"))
                return
            result = self.add_tell(nick, to_nick, msg_text)
            self.send_message(channel, result)

        # ── WHOIS ──
        elif command == f"{p}whois":
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}whois <nick>"))
                return
            target = Sanitizer.sanitize_nick(parts[1])
            if not target:
                self.send_message(channel, self._error("Invalid nick"))
                return
            self.pending_whois[target.lower()] = {'channel': channel, 'data': {}}
            self.send_raw(f"WHOIS {target}")

        # ── HTTP Status ──
        elif command in (f"{p}http", f"{p}h"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}http <code>"))
                return
            try:
                code = int(parts[1])
            except ValueError:
                self.send_message(channel, self._error("Invalid code — must be a number"))
                return
            info = self.http_status_info(code)
            if info:
                self.send_message(channel, info)
            else:
                self.send_message(channel, self._error(f"Unknown HTTP status code: {code}"))

        # ── DNS ──
        elif command in (f"{p}dns", f"{p}nslookup"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}dns <hostname>"))
                return
            hostname = Sanitizer.sanitize_hostname(parts[1])
            if not hostname:
                self.send_message(channel, self._error("Invalid hostname"))
                return
            result = self.get_dns(hostname)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        # ── GeoIP ──
        elif command in (f"{p}geo", f"{p}geoip", f"{p}ip"):
            if len(parts) < 2:
                self.send_message(channel, self._error(f"Usage: {p}geo <ip|hostname>"))
                return
            hostname = Sanitizer.sanitize_hostname(parts[1])
            if not hostname:
                self.send_message(channel, self._error("Invalid IP or hostname"))
                return
            result = self.get_geo(hostname)
            for line in result.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.2)

        # ── Help ──
        elif command == f"{p}help":
            lines = [
                self._header(f"le0 Bot Commands {BOX_SEP} Help Menu"),
                f" {B}{C.CYAN}[Weather]{R}  {COLOR_ACCENT}{p}weather/w <loc>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}forecast/f <loc>{R}",
                f" {B}{C.YELLOW}[Info]{R}     {COLOR_ACCENT}{p}urban/ud <term>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}time [loc]{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}http <code>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}dns <host>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}geo <ip>{R}",
                f" {B}{C.GREEN}[Net]{R}      {COLOR_ACCENT}{p}title/t <url>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}isup/up <host>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}shorten <url>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}stock <tick>{R}",
                f" {B}{C.LIGHT_BLUE}[Lookup]{R}   {COLOR_ACCENT}{p}wiki/wi <topic>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}define/def <word>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}tr <lang> <text>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}whois <nick>{R}",
                f" {B}{C.CYAN}[Fun]{R}      {COLOR_ACCENT}{p}coin/flip{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}roll/dice [XdY]{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}8ball/8 <q>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}rps <r/p/s>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}fact{R}",
                f" {B}{C.YELLOW}[Social]{R}   {COLOR_ACCENT}{p}quote{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}addquote <text>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}tell <nick> <msg>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}paste <text>{R}",
                f" {B}{C.LIGHT_GREEN}[Utility]{R}  {COLOR_ACCENT}{p}seen <nick>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}ping{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}uptime{R}",
                f" {B}{C.ORANGE}[Tools]{R}    {COLOR_ACCENT}{p}calc <expr>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}hash <text>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}base64/b64 <e/d>{R}",
                f" {B}{C.LIGHT_BLUE}[Text]{R}     {COLOR_ACCENT}{p}reverse <text>{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}mock <text>{R}",
            ]
            if self._is_admin(hostmask):
                lines.append(f" {B}{C.RED}[Admin]{R}    {COLOR_ACCENT}{p}join{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}part{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}quit{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}say{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}nick{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}kick{R} {COLOR_PRIMARY}{BOX_SEP}{R} {COLOR_ACCENT}{p}raw{R}")
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
                        if self.nickserv_pass:
                            print("Identifying with NickServ...")
                            self.send_raw(f"PRIVMSG NickServ :IDENTIFY {self.nickserv_pass}")
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

                    # ── WHOIS numeric replies ──
                    whois_m = re.match(r':\S+ (\d{3}) \S+ (\S+) (.+)', line)
                    if whois_m:
                        numeric = whois_m.group(1)
                        target_nick = whois_m.group(2).lower()
                        rest = whois_m.group(3).lstrip(':')
                        if target_nick in self.pending_whois:
                            d = self.pending_whois[target_nick]['data']
                            if numeric == '311':
                                # :server 311 me nick user host * :realname
                                parts311 = rest.split(None, 3)
                                if len(parts311) >= 4:
                                    d['user'] = parts311[0]
                                    d['host'] = parts311[1]
                                    d['realname'] = parts311[3].lstrip(':')
                            elif numeric == '312':
                                parts312 = rest.split(None, 1)
                                d['server'] = parts312[0]
                            elif numeric == '317':
                                parts317 = rest.split()
                                if parts317:
                                    try:
                                        idle = int(parts317[0])
                                        h, m, s = idle // 3600, (idle % 3600) // 60, idle % 60
                                        d['idle'] = f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")
                                    except ValueError:
                                        pass
                            elif numeric == '319':
                                d['channels'] = rest.lstrip(':').strip()
                            elif numeric == '330':
                                parts330 = rest.split(None, 1)
                                d['account'] = parts330[0]
                            elif numeric == '671':
                                d['secure'] = True
                            elif numeric == '301':
                                d['away'] = rest.lstrip(':')
                            elif numeric == '318':
                                # End of WHOIS — format and send
                                info = self.pending_whois.pop(target_nick)
                                ch  = info['channel']
                                dat = info['data']
                                nick_disp = target_nick
                                lines_w = [self._header(f"WHOIS: {nick_disp}")]
                                if 'realname' in dat:
                                    lines_w.append(self._arrow_line(
                                        f"{B}{C.CYAN}User{R}     {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{dat.get('user','?')}@{dat.get('host','?')}{R}"
                                        f"  ({dat['realname']})"
                                    ))
                                if 'server' in dat:
                                    lines_w.append(self._arrow_line(
                                        f"{B}{C.YELLOW}Server{R}   {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{dat['server']}{R}"
                                    ))
                                if 'account' in dat:
                                    lines_w.append(self._arrow_line(
                                        f"{B}{C.LIGHT_GREEN}Account{R}  {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{dat['account']}{R}"
                                    ))
                                if 'idle' in dat:
                                    lines_w.append(self._arrow_line(
                                        f"{B}{C.ORANGE}Idle{R}     {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{dat['idle']}{R}"
                                    ))
                                if 'channels' in dat:
                                    lines_w.append(self._arrow_line(
                                        f"{B}{C.LIGHT_BLUE}Channels{R} {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{dat['channels']}{R}"
                                    ))
                                if dat.get('secure'):
                                    lines_w.append(self._arrow_line(
                                        f"{B}{C.LIGHT_GREEN}TLS{R}      {COLOR_PRIMARY}|{R} {COLOR_ACCENT}Secure connection{R}"
                                    ))
                                if 'away' in dat:
                                    lines_w.append(self._arrow_line(
                                        f"{B}{C.GREY}Away{R}     {COLOR_PRIMARY}|{R} {COLOR_ACCENT}{dat['away']}{R}"
                                    ))
                                for wl in lines_w:
                                    self.send_message(ch, wl)
                                    time.sleep(0.2)

                    # Parse messages: :nick!user@host PRIVMSG #channel :message
                    match = re.match(r':(.+?)!(.+?) PRIVMSG (.+?) :(.+)', line)

                    if match:
                        nick = match.group(1)
                        userhost = match.group(2)
                        channel = match.group(3)
                        message = match.group(4)
                        hostmask = f"{nick}!{userhost}"

                        if nick == self.nickname:
                            continue

                        self.track_seen(nick, channel, message)

                        # Deliver pending tells
                        self.deliver_tells(nick, channel)

                        # Auto-reply to duck hunt (Sopel/CloudBot duck plugin)
                        # Strip IRC formatting before pattern matching
                        clean_msg = re.sub(r'\x03\d{0,2}(,\d{0,2})?|\x02|\x1d|\x1f|\x0f|\x16', '', message)
                        if re.search(r'\\[_^][^\s]*<', clean_msg) and 'quack' in clean_msg.lower():
                            delay = random.uniform(2, 8)
                            time.sleep(delay)
                            action = random.choice(['bang', 'bef'])
                            self.send_message(channel, action)

                        if message.startswith(self.command_prefix):
                            self.handle_command(channel, nick, hostmask, message)

            except KeyboardInterrupt:
                print("\nShutting down...")
                self.send_raw("QUIT :le0 shutting down")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(5)


if __name__ == "__main__":
    config_arg = sys.argv[1] if len(sys.argv) > 1 else "config"
    config_file = config_arg if config_arg.endswith('.py') else config_arg + ".py"
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file)
    if not os.path.isfile(config_path):
        print(f"Error: config file '{config_file}' not found")
        sys.exit(1)
    spec = importlib.util.spec_from_file_location("config", config_path)
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)

    bot = IRCBot(
        server=config.SERVER,
        port=config.PORT,
        nickname=config.NICKNAME,
        channels=config.CHANNELS,
        use_ssl=config.USE_SSL,
        verify_ssl=config.VERIFY_SSL,
        password=config.PASSWORD,
        command_prefix=config.COMMAND_PREFIX,
        nickserv_pass=config.NICKSERV_PASS,
        sasl_username=config.SASL_USERNAME,
        sasl_password=config.SASL_PASSWORD,
        admins=getattr(config, 'ADMINS', []),
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
    ║   • IRC Bot v2.0 - Enhanced Theme    ║
    ╠═══════════════════════════════════════╣
    """)
    p = bot.command_prefix
    print(f"    ║  Weather  │ {p}weather/w   {p}forecast/f   ║")
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
