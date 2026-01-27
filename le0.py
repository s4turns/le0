#!/usr/bin/env python3
"""
Simple IRC Bot with Weather Commands
"""

import socket
import ssl
import time
import re
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


class IRCBot:
    def __init__(self, server: str, port: int, nickname: str, channels: list, 
                 use_ssl: bool = False, password: Optional[str] = None,
                 command_prefix: str = "%"):
        """
        Initialize the IRC bot.
        
        Args:
            server: IRC server address
            port: IRC server port
            nickname: Bot's nickname
            channels: List of channels to join
            use_ssl: Whether to use SSL/TLS
            password: Server password (optional)
            command_prefix: Character(s) to trigger commands (default: "%")
        """
        self.server = server
        self.port = port
        self.nickname = nickname
        self.channels = channels
        self.use_ssl = use_ssl
        self.password = password
        self.command_prefix = command_prefix
        self.irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Weather API - using wttr.in (no API key needed)
        self.weather_api = "https://wttr.in/{location}?format=j1"
        
        # Backup weather API - OpenMeteo (no API key needed)
        self.geocoding_api = "https://geocoding-api.open-meteo.com/v1/search?name={location}&count=1&language=en&format=json"
        self.openmeteo_api = "https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m,wind_direction_10m,pressure_msl,cloud_cover,visibility,uv_index&daily=weather_code,temperature_2m_max,temperature_2m_min,sunrise,sunset,uv_index_max,precipitation_sum,precipitation_probability_max&temperature_unit=celsius&wind_speed_unit=kmh&forecast_days=3&timezone=auto"
        
        # Track last seen users
        self.seen_users = {}
        
        # 8ball responses
        self.eightball_responses = [
            "It is certain", "It is decidedly so", "Without a doubt", "Yes definitely",
            "You may rely on it", "As I see it, yes", "Most likely", "Outlook good",
            "Yes", "Signs point to yes", "Reply hazy, try again", "Ask again later",
            "Better not tell you now", "Cannot predict now", "Concentrate and ask again",
            "Don't count on it", "My reply is no", "My sources say no", "Outlook not so good",
            "Very doubtful"
        ]
        
        # Weather code descriptions for OpenMeteo
        self.weather_codes = {
            0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast",
            45: "Foggy", 48: "Depositing rime fog",
            51: "Light drizzle", 53: "Moderate drizzle", 55: "Dense drizzle",
            61: "Slight rain", 63: "Moderate rain", 65: "Heavy rain",
            71: "Slight snow", 73: "Moderate snow", 75: "Heavy snow",
            77: "Snow grains", 80: "Slight rain showers", 81: "Moderate rain showers",
            82: "Violent rain showers", 85: "Slight snow showers", 86: "Heavy snow showers",
            95: "Thunderstorm", 96: "Thunderstorm with slight hail", 99: "Thunderstorm with heavy hail"
        }
        
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
        self.irc.send(bytes(message + "\r\n", "UTF-8"))
        
    def send_message(self, target: str, message: str):
        """Send a message to a channel or user."""
        self.send_raw(f"PRIVMSG {target} :{message}")
        
    def join_channel(self, channel: str):
        """Join a channel."""
        self.send_raw(f"JOIN {channel}")
        print(f"Joined {channel}")
        
    def get_weather(self, location: str) -> str:
        """
        Get weather information for a location using OpenMeteo API.
        
        Args:
            location: City name or location query
            
        Returns:
            Formatted weather string with colors
        """
        try:
            # First, geocode the location
            geocode_url = self.geocoding_api.format(location=location)
            geo_response = requests.get(geocode_url, timeout=5)
            
            if geo_response.status_code != 200:
                return f"{IRCColors.color('✗', IRCColors.RED)} Could not find location '{location}'"
            
            geo_data = geo_response.json()
            if not geo_data.get('results'):
                return f"{IRCColors.color('✗', IRCColors.RED)} Could not find location '{location}'"
            
            result = geo_data['results'][0]
            lat = result['latitude']
            lon = result['longitude']
            city_name = result['name']
            country = result.get('country', '')
            
            # Get weather data
            weather_url = self.openmeteo_api.format(lat=lat, lon=lon)
            weather_response = requests.get(weather_url, timeout=5)
            
            if weather_response.status_code != 200:
                return f"{IRCColors.color('✗', IRCColors.RED)} Error fetching weather data"
            
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
            uv_index = current.get('uv_index', 0)
            weather_code = current['weather_code']
            
            # Get sunrise/sunset from daily data
            sunrise = daily['sunrise'][0].split('T')[1][:5] if daily.get('sunrise') else 'N/A'
            sunset = daily['sunset'][0].split('T')[1][:5] if daily.get('sunset') else 'N/A'
            
            # Get weather description
            desc = self.weather_codes.get(weather_code, "Unknown")
            
            # Convert wind direction to compass
            directions = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE',
                         'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW']
            wind_compass = directions[int((wind_dir + 11.25) / 22.5) % 16]
            
            # Get temperature colors
            temp_color = IRCColors.temp_color(temp_c)
            feels_color = IRCColors.temp_color(feels_c)
            
            # UV Index color
            if uv_index < 3:
                uv_color = IRCColors.GREEN
            elif uv_index < 6:
                uv_color = IRCColors.YELLOW
            elif uv_index < 8:
                uv_color = IRCColors.ORANGE
            else:
                uv_color = IRCColors.RED
            
            # Format with colors
            location_display = f"{city_name}, {country}" if country else city_name
            location_text = IRCColors.bold(IRCColors.color(location_display, IRCColors.CYAN))
            desc_text = IRCColors.color(desc, IRCColors.LIGHT_GREY)
            temp_text = f"{IRCColors.color(f'{temp_c}°C', temp_color)} ({IRCColors.color(f'{temp_f}°F', temp_color)})"
            feels_text = f"{IRCColors.color(f'{feels_c}°C', feels_color)} ({IRCColors.color(f'{feels_f}°F', feels_color)})"
            humidity_text = IRCColors.color(f"{humidity}%", IRCColors.LIGHT_BLUE)
            wind_text = IRCColors.color(f"{wind_speed}km/h {wind_compass}", IRCColors.LIGHT_GREEN)
            pressure_text = IRCColors.color(f"{pressure}hPa", IRCColors.LIGHT_GREY)
            cloud_text = IRCColors.color(f"{cloud_cover}%", IRCColors.LIGHT_GREY)
            vis_text = IRCColors.color(f"{visibility_km}km", IRCColors.LIGHT_CYAN)
            uv_text = IRCColors.color(f"{uv_index:.1f}", uv_color)
            sunrise_text = IRCColors.color(sunrise, IRCColors.YELLOW)
            sunset_text = IRCColors.color(sunset, IRCColors.ORANGE)
            
            # Build multi-line output
            line1 = (
                f"{location_text} {IRCColors.GREY}→{IRCColors.RESET} {desc_text} {IRCColors.GREY}|{IRCColors.RESET} "
                f"🌡️ {temp_text} {IRCColors.GREY}|{IRCColors.RESET} "
                f"Feels: {feels_text}"
            )
            
            line2 = (
                f"💧 {humidity_text} {IRCColors.GREY}|{IRCColors.RESET} "
                f"💨 {wind_text} {IRCColors.GREY}|{IRCColors.RESET} "
                f"☁️ {cloud_text} {IRCColors.GREY}|{IRCColors.RESET} "
                f"🔆 UV: {uv_text}"
            )
            
            line3 = (
                f"📊 {pressure_text} {IRCColors.GREY}|{IRCColors.RESET} "
                f"👁️ {vis_text} {IRCColors.GREY}|{IRCColors.RESET} "
                f"🌅 {sunrise_text} {IRCColors.GREY}|{IRCColors.RESET} "
                f"🌇 {sunset_text}"
            )
            
            return f"{line1}\n{line2}\n{line3}"
            
        except requests.exceptions.Timeout:
            return f"{IRCColors.color('✗', IRCColors.RED)} Request timed out - weather service may be unavailable"
        except requests.exceptions.RequestException as e:
            return f"{IRCColors.color('✗', IRCColors.RED)} Network error: {str(e)[:50]}"
        except (KeyError, IndexError, ValueError) as e:
            return f"{IRCColors.color('✗', IRCColors.RED)} Error parsing weather data"
    
    def get_forecast(self, location: str, days: int = 3) -> list:
        """
        Get weather forecast for a location using OpenMeteo API.
        
        Args:
            location: City name or location query
            days: Number of days to forecast (max 3)
            
        Returns:
            List of forecast strings with colors
        """
        try:
            # First, geocode the location
            geocode_url = self.geocoding_api.format(location=location)
            geo_response = requests.get(geocode_url, timeout=5)
            
            if geo_response.status_code != 200:
                return [f"{IRCColors.color('✗', IRCColors.RED)} Could not find location '{location}'"]
            
            geo_data = geo_response.json()
            if not geo_data.get('results'):
                return [f"{IRCColors.color('✗', IRCColors.RED)} Could not find location '{location}'"]
            
            result = geo_data['results'][0]
            lat = result['latitude']
            lon = result['longitude']
            
            # Get weather data
            weather_url = self.openmeteo_api.format(lat=lat, lon=lon)
            weather_response = requests.get(weather_url, timeout=5)
            
            if weather_response.status_code != 200:
                return [f"{IRCColors.color('✗', IRCColors.RED)} Error fetching forecast data"]
            
            data = weather_response.json()
            daily = data['daily']
            
            forecasts = []
            for i in range(min(days, 3)):
                date = daily['time'][i]
                max_temp_c = int(daily['temperature_2m_max'][i])
                min_temp_c = int(daily['temperature_2m_min'][i])
                max_temp_f = int(max_temp_c * 9/5 + 32)
                min_temp_f = int(min_temp_c * 9/5 + 32)
                weather_code = daily['weather_code'][i]
                desc = self.weather_codes.get(weather_code, "Unknown")
                
                # Additional data
                uv_max = daily.get('uv_index_max', [0])[i]
                precip_sum = daily.get('precipitation_sum', [0])[i]
                precip_prob = daily.get('precipitation_probability_max', [0])[i]
                
                # Get colors
                max_color = IRCColors.temp_color(max_temp_c)
                min_color = IRCColors.temp_color(min_temp_c)
                
                # UV color
                if uv_max < 3:
                    uv_color = IRCColors.GREEN
                elif uv_max < 6:
                    uv_color = IRCColors.YELLOW
                elif uv_max < 8:
                    uv_color = IRCColors.ORANGE
                else:
                    uv_color = IRCColors.RED
                
                date_text = IRCColors.bold(IRCColors.color(date, IRCColors.CYAN))
                desc_text = IRCColors.color(desc, IRCColors.LIGHT_GREY)
                high_text = f"{IRCColors.color(f'{max_temp_c}°C', max_color)} ({IRCColors.color(f'{max_temp_f}°F', max_color)})"
                low_text = f"{IRCColors.color(f'{min_temp_c}°C', min_color)} ({IRCColors.color(f'{min_temp_f}°F', min_color)})"
                uv_text = IRCColors.color(f"{uv_max:.1f}", uv_color)
                precip_text = IRCColors.color(f"{precip_sum:.1f}mm", IRCColors.LIGHT_BLUE)
                precip_prob_text = IRCColors.color(f"{precip_prob}%", IRCColors.CYAN)
                
                forecast_msg = (
                    f"{date_text} {IRCColors.GREY}→{IRCColors.RESET} {desc_text} {IRCColors.GREY}|{IRCColors.RESET} "
                    f"High: {high_text} {IRCColors.GREY}|{IRCColors.RESET} "
                    f"Low: {low_text} {IRCColors.GREY}|{IRCColors.RESET} "
                    f"UV: {uv_text} {IRCColors.GREY}|{IRCColors.RESET} "
                    f"💧 {precip_text} ({precip_prob_text})"
                )
                forecasts.append(forecast_msg)
            
            return forecasts
            
        except requests.exceptions.Timeout:
            return [f"{IRCColors.color('✗', IRCColors.RED)} Request timed out - weather service may be unavailable"]
        except requests.exceptions.RequestException as e:
            return [f"{IRCColors.color('✗', IRCColors.RED)} Network error: {str(e)[:50]}"]
        except (KeyError, IndexError, ValueError) as e:
            return [f"{IRCColors.color('✗', IRCColors.RED)} Error parsing forecast data"]
    
    def get_urban_definition(self, term: str) -> str:
        """Get Urban Dictionary definition."""
        try:
            response = requests.get(
                f"https://api.urbandictionary.com/v0/define?term={term}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data['list']:
                    definition = data['list'][0]
                    word = definition['word']
                    meaning = definition['definition'].replace('[', '').replace(']', '')
                    permalink = definition['permalink']
                    
                    # Truncate if too long
                    if len(meaning) > 250:
                        meaning = meaning[:247] + "..."
                    
                    word_text = IRCColors.bold(IRCColors.color(word, IRCColors.ORANGE))
                    link_text = IRCColors.color(IRCColors.UNDERLINE + permalink + IRCColors.RESET, IRCColors.LIGHT_BLUE)
                    
                    return f"{word_text} {IRCColors.GREY}→{IRCColors.RESET} {meaning}\n{IRCColors.GREY}└─{IRCColors.RESET} {link_text}"
                else:
                    return f"{IRCColors.color('✗', IRCColors.RED)} No definition found for '{term}'"
            else:
                return f"{IRCColors.color('✗', IRCColors.RED)} Error fetching definition"
                
        except Exception as e:
            return f"{IRCColors.color('✗', IRCColors.RED)} Error: {str(e)}"
    
    def get_time(self, location: str = None) -> str:
        """Get current time for a location."""
        try:
            if location:
                # Use worldtimeapi.org which is more reliable
                # First try to geocode to get timezone
                geocode_url = self.geocoding_api.format(location=location)
                geo_response = requests.get(geocode_url, timeout=5)
                
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('results'):
                        result = geo_data['results'][0]
                        city_name = result['name']
                        # Get timezone from coordinates (simplified - just show UTC for now)
                        current_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                        time_text = IRCColors.bold(IRCColors.color(current_time, IRCColors.LIGHT_CYAN))
                        loc_text = IRCColors.color(city_name, IRCColors.CYAN)
                        return f"🕐 {time_text} (showing UTC, local time varies by timezone)"
                
                return f"{IRCColors.color('✗', IRCColors.RED)} Could not find location '{location}'"
            else:
                # Return UTC time
                current_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                time_text = IRCColors.bold(IRCColors.color(current_time, IRCColors.LIGHT_CYAN))
                return f"🕐 {time_text}"
                
        except Exception as e:
            return f"{IRCColors.color('✗', IRCColors.RED)} Error getting time"
    
    def coin_flip(self) -> str:
        """Flip a coin."""
        import random
        result = random.choice(["Heads", "Tails"])
        color = IRCColors.YELLOW if result == "Heads" else IRCColors.LIGHT_GREY
        return f"🪙 {IRCColors.bold(IRCColors.color(result, color))}"
    
    def roll_dice(self, dice_str: str = "1d6") -> str:
        """Roll dice (e.g., 2d6, 1d20)."""
        import random
        try:
            if 'd' not in dice_str.lower():
                dice_str = f"1d{dice_str}"
            
            num, sides = dice_str.lower().split('d')
            num = int(num) if num else 1
            sides = int(sides)
            
            if num > 20 or sides > 1000:
                return f"{IRCColors.color('✗', IRCColors.RED)} Maximum 20 dice with 1000 sides each"
            
            rolls = [random.randint(1, sides) for _ in range(num)]
            total = sum(rolls)
            
            dice_text = IRCColors.bold(IRCColors.color(f"{num}d{sides}", IRCColors.CYAN))
            rolls_text = IRCColors.color(str(rolls), IRCColors.LIGHT_GREY)
            total_text = IRCColors.bold(IRCColors.color(str(total), IRCColors.YELLOW))
            
            if num == 1:
                return f"🎲 {dice_text} {IRCColors.GREY}→{IRCColors.RESET} {total_text}"
            else:
                return f"🎲 {dice_text} {IRCColors.GREY}→{IRCColors.RESET} {rolls_text} = {total_text}"
                
        except Exception as e:
            return f"{IRCColors.color('✗', IRCColors.RED)} Invalid dice format (use like 2d6 or 1d20)"
    
    def eightball(self, question: str) -> str:
        """Magic 8-ball."""
        import random
        if not question.strip():
            return f"{IRCColors.color('✗', IRCColors.RED)} Ask me a question!"
        
        response = random.choice(self.eightball_responses)
        return f"🎱 {IRCColors.bold(IRCColors.color(response, IRCColors.PURPLE))}"
    
    def track_seen(self, nick: str, channel: str, message: str):
        """Track when users were last seen."""
        self.seen_users[nick.lower()] = {
            'nick': nick,
            'channel': channel,
            'message': message,
            'time': time.time()
        }
    
    def get_seen(self, nick: str) -> str:
        """Get when a user was last seen."""
        nick_lower = nick.lower()
        if nick_lower in self.seen_users:
            user = self.seen_users[nick_lower]
            elapsed = int(time.time() - user['time'])
            
            # Format time
            if elapsed < 60:
                time_str = f"{elapsed} seconds ago"
            elif elapsed < 3600:
                time_str = f"{elapsed // 60} minutes ago"
            elif elapsed < 86400:
                time_str = f"{elapsed // 3600} hours ago"
            else:
                time_str = f"{elapsed // 86400} days ago"
            
            nick_text = IRCColors.bold(IRCColors.color(user['nick'], IRCColors.CYAN))
            time_text = IRCColors.color(time_str, IRCColors.LIGHT_GREY)
            channel_text = IRCColors.color(user['channel'], IRCColors.YELLOW)
            msg_text = IRCColors.color(user['message'][:100], IRCColors.LIGHT_GREY)
            
            return f"{nick_text} was last seen {time_text} in {channel_text} saying: {msg_text}"
        else:
            return f"{IRCColors.color('✗', IRCColors.RED)} Haven't seen {nick} yet"
    
    def handle_command(self, channel: str, nick: str, message: str):
        """
        Handle bot commands.
        
        Args:
            channel: Channel where command was sent
            nick: Nickname of user who sent command
            message: The message/command
        """
        parts = message.strip().split()
        
        if not parts:
            return
            
        command = parts[0].lower()
        
        # Weather command: %weather <location>
        if command == f"{self.command_prefix}weather" or command == f"{self.command_prefix}w":
            if len(parts) < 2:
                self.send_message(channel, f"{nick}: Usage: {self.command_prefix}weather <location>")
                return
            
            location = " ".join(parts[1:])
            weather = self.get_weather(location)
            # Split by newlines for multi-line output
            for line in weather.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.3)  # Small delay between lines
        
        # Forecast command: %forecast <location> [days]
        elif command == f"{self.command_prefix}forecast" or command == f"{self.command_prefix}f":
            if len(parts) < 2:
                self.send_message(channel, f"{nick}: Usage: {self.command_prefix}forecast <location> [days]")
                return
            
            # Check if last part is a number
            days = 3
            location_parts = parts[1:]
            
            if location_parts[-1].isdigit():
                days = min(int(location_parts[-1]), 3)
                location_parts = location_parts[:-1]
            
            location = " ".join(location_parts)
            forecasts = self.get_forecast(location, days)
            
            header = f"{IRCColors.bold(IRCColors.color('Forecast', IRCColors.CYAN))} for {IRCColors.color(location, IRCColors.YELLOW)}"
            self.send_message(channel, header)
            for forecast in forecasts:
                self.send_message(channel, forecast)
                time.sleep(0.5)  # Anti-flood delay
        
        # Urban Dictionary: %urban <term>
        elif command == f"{self.command_prefix}urban" or command == f"{self.command_prefix}ud":
            if len(parts) < 2:
                self.send_message(channel, f"{nick}: Usage: {self.command_prefix}urban <term>")
                return
            
            term = " ".join(parts[1:])
            definition = self.get_urban_definition(term)
            # Split by newlines for multi-line output
            for line in definition.split('\n'):
                self.send_message(channel, line)
                time.sleep(0.3)  # Small delay between lines
        
        # Time command: %time [location]
        elif command == f"{self.command_prefix}time":
            location = " ".join(parts[1:]) if len(parts) > 1 else None
            time_str = self.get_time(location)
            self.send_message(channel, time_str)
        
        # Coin flip: %coin or %flip
        elif command == f"{self.command_prefix}coin" or command == f"{self.command_prefix}flip":
            result = self.coin_flip()
            self.send_message(channel, result)
        
        # Dice roll: %roll [XdY]
        elif command == f"{self.command_prefix}roll" or command == f"{self.command_prefix}dice":
            dice_str = parts[1] if len(parts) > 1 else "1d6"
            result = self.roll_dice(dice_str)
            self.send_message(channel, result)
        
        # 8ball: %8ball <question>
        elif command == f"{self.command_prefix}8ball" or command == f"{self.command_prefix}8":
            question = " ".join(parts[1:])
            result = self.eightball(question)
            self.send_message(channel, result)
        
        # Seen: %seen <nick>
        elif command == f"{self.command_prefix}seen":
            if len(parts) < 2:
                self.send_message(channel, f"{nick}: Usage: {self.command_prefix}seen <nick>")
                return
            
            target_nick = parts[1]
            result = self.get_seen(target_nick)
            self.send_message(channel, result)
        
        # Help command
        elif command == f"{self.command_prefix}help":
            self.send_message(channel, f"{IRCColors.bold(IRCColors.color('Available commands:', IRCColors.CYAN))}")
            self.send_message(channel, f"{IRCColors.YELLOW}Weather:{IRCColors.RESET} {self.command_prefix}weather/w <location>, {self.command_prefix}forecast/f <location> [days]")
            self.send_message(channel, f"{IRCColors.YELLOW}Info:{IRCColors.RESET} {self.command_prefix}urban/ud <term>, {self.command_prefix}time [location]")
            self.send_message(channel, f"{IRCColors.YELLOW}Fun:{IRCColors.RESET} {self.command_prefix}coin/flip, {self.command_prefix}roll/dice [XdY], {self.command_prefix}8ball/8 <question>")
            self.send_message(channel, f"{IRCColors.YELLOW}Utility:{IRCColors.RESET} {self.command_prefix}seen <nick>, {self.command_prefix}help")
    
    def run(self):
        """Main bot loop."""
        self.connect()
        
        buffer = ""
        connected = False
        
        # Wait for end of MOTD (376) or ERR_NOMOTD (422) before joining channels
        print("Waiting for server connection to complete...")
        while not connected:
            try:
                buffer += self.irc.recv(2048).decode("UTF-8", errors="ignore")
                lines = buffer.split("\r\n")
                buffer = lines.pop()
                
                for line in lines:
                    print(line)
                    
                    # Respond to PING
                    if line.startswith("PING"):
                        pong = line.replace("PING", "PONG")
                        self.send_raw(pong)
                    
                    # Check for end of MOTD or no MOTD
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
                    
                    # Respond to PING
                    if line.startswith("PING"):
                        pong = line.replace("PING", "PONG")
                        self.send_raw(pong)
                        continue
                    
                    # Parse messages
                    # Format: :nick!user@host PRIVMSG #channel :message
                    match = re.match(r':(.+?)!.+? PRIVMSG (.+?) :(.+)', line)
                    
                    if match:
                        nick = match.group(1)
                        channel = match.group(2)
                        message = match.group(3)
                        
                        # Ignore messages from ourselves
                        if nick == self.nickname:
                            continue
                        
                        # Track user activity for %seen command
                        self.track_seen(nick, channel, message)
                        
                        # Handle commands (messages starting with command_prefix)
                        if message.startswith(self.command_prefix):
                            self.handle_command(channel, nick, message)
                            
            except KeyboardInterrupt:
                print("\nShutting down...")
                self.send_raw("QUIT :Bot shutting down")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(5)


if __name__ == "__main__":
    # Example configuration
    bot = IRCBot(
        server="irc.blcknd.network",    # IRC server
        port=6697,                      # Port (6697 for SSL, 6667 for non-SSL)
        nickname="le0",                 # Your bot's nickname
        channels=["#blcknd"],           # Channels to join
        use_ssl=True,                   # Use SSL/TLS
        password=None,                  # Server password (if needed)
        command_prefix="%"              # Command trigger (default: "%")
    )
    
    print("Starting IRC Bot: le0")
    print("Commands:")
    print(f"  Weather: {bot.command_prefix}weather/w <location>, {bot.command_prefix}forecast/f <location> [days]")
    print(f"  Info: {bot.command_prefix}urban/ud <term>, {bot.command_prefix}time [location]")
    print(f"  Fun: {bot.command_prefix}coin/flip, {bot.command_prefix}roll/dice [XdY], {bot.command_prefix}8ball/8 <question>")
    print(f"  Utility: {bot.command_prefix}seen <nick>, {bot.command_prefix}help")
    print("\nPress Ctrl+C to stop the bot\n")
    
    bot.run()
