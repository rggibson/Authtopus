# The "from" address for support emails
EMAIL_SENDER = "support@example.com"

# Text for email verification emails
EMAIL_VERIFY_SUBJECT = "Please verify your email address for Example.com"
EMAIL_VERIFY_BODY = """
Dear {0}:

Please verify your email address with Example.com by either
clicking the link below, or copying the link address and pasting it
into your browser's address bar:

{1}

Cheers,

Example.com
"""

# Text for password reset emails
EMAIL_PASSWORD_RESET_SUBJECT = "Password reset for Example.com"
EMAIL_PASSWORD_RESET_BODY = """
Dear {0}:

A request to reset your password for your Example.com account was recently
submitted.  To proceed, click the link below or copy the link address and
paste it into your browser's address bar:

{1}

If this email was sent in error, please disregard.

Cheers,

Example.com
"""

# How long different token types are good for before becoming invalid
TOKEN_LIFE_HOURS = {
    'auth': 4,
    'verify_email': 24,
    'password_reset': 3
}

# How many unexpired tokens a user can have
MAX_PASSWORD_RESET_TOKENS = 3
MAX_VERIFY_EMAIL_TOKENS_PER_EMAIL = 3

# Max number of tokens deleted of each token type each time cron job is run
TOKEN_DELETE_LIMIT = 10000

# Max number of users with unverified email addresses to delete each time cron
# job is run
UNVERIFIED_USER_DELETE_LIMIT = 1000

# How long before a user with no verified email address is deleted from the
# last time the user was updated
UNVERIFIED_USER_LIFE_HOURS = 72
