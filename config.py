# ─── le0 IRC Bot Configuration ────────────────────────────────────

# Connection
SERVER = "irc.blcknd.network"
PORT = 6697                     # 6697 for SSL, 6667 for non-SSL
NICKNAME = "le0"
CHANNELS = ["#d0m3r", "#blcknd"]
COMMAND_PREFIX = "%"

# SSL / Auth
USE_SSL = True
VERIFY_SSL = True               # False to allow self-signed/unverified certs
PASSWORD = None                 # Server password (if needed)
NICKSERV_PASS = None            # NickServ identify password (if needed)
SASL_USERNAME = None            # SASL plain username (if needed)
SASL_PASSWORD = None            # SASL plain password (if needed)
