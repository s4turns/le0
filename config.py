# ─── le0 IRC Bot Configuration ────────────────────────────────────

# Connection
SERVER = "irc.blcknd.network"
PORT = 6697                     # 6697 for SSL, 6667 for non-SSL
NICKNAME = "le0"
CHANNELS = ["#d0m3r", "#blcknd", "#security"]
COMMAND_PREFIX = "%"

# Admin hostmasks (nick!user@host format, wildcards supported)
# Examples: "*!*@myhost.isp.net"  "*!*@*.myisp.net"  "mynick!*@*"
ADMINS = ["*!*@*.interdo.me", "*!*@*interdome.blcknd.network"]

# SSL / Auth
USE_SSL = True
VERIFY_SSL = True               # False to allow self-signed/unverified certs
PASSWORD = None                 # Server password (if needed)
NICKSERV_PASS = None            # NickServ identify password (if needed)
SASL_USERNAME = None            # SASL plain username (if needed)
SASL_PASSWORD = None            # SASL plain password (if needed)

# NVD API key — set via environment variable instead:
#   export NVD_API_KEY="your-key-here"
# Without a key: 5 req/30s limit. With a key: 50 req/30s.

# YouTube Data API v3 key — set via environment variable:
#   export YOUTUBE_API_KEY="your-key-here"
# Enables full cards (title, channel, views, likes, length, description) for
# YouTube links pasted in-channel. Without a key, links show title + channel only.
