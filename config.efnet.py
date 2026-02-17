# ─── le0 IRC Bot Configuration ────────────────────────────────────

# Connection
SERVER = "efnet.tngnet.nl"
PORT = 6697                     # 6697 for SSL, 6667 for non-SSL
NICKNAME = "le0"
CHANNELS = ["#201337,#irc40,#:heart:"]
COMMAND_PREFIX = "%"

# SSL / Auth
USE_SSL = True
VERIFY_SSL = False               # False to allow self-signed/unverified certs
PASSWORD = None                 # Server password (if needed)
NICKSERV_PASS = None            # NickServ identify password (if needed)
SASL_USERNAME = None            # SASL plain username (if needed)
SASL_PASSWORD = None            # SASL plain password (if needed)
