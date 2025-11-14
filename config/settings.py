from pathlib import Path
import os
from dotenv import load_dotenv
from datetime import timedelta

# Load .env
load_dotenv()

BASE_DIR = Path(__file__).resolve(strict=True).parent.parent

# ===============================================================
# 🔐 SECURITY
# ===============================================================
SECRET_KEY = os.getenv('SECRET_KEY', 'dummy-secret-key')
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

ALLOWED_HOSTS = [
    "oppvenuz-backend.onrender.com",
    "oppvenuz-backend-new.onrender.com",
    "localhost",
    "127.0.0.1"
]

# ===============================================================
# 📩 EMAIL / SMS
# ===============================================================
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL")
TEXT_LOCAL_API_KEY = os.getenv("TEXT_LOCAL_API_KEY")
TEXTLOCAL_SENDER = os.getenv("TEXTLOCAL_SENDER", "OPPVNZ")

# ===============================================================
# 🔐 AUTHENTICATION
# ===============================================================
AUTHENTICATION_BACKENDS = [
    'vendor.auth_backend.VendorAuthBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# ===============================================================
# 🧩 INSTALLED APPS
# ===============================================================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'drf_yasg',
    'rest_framework',
    "oauth2_provider",

    'admin_master',
    'vendor',
    'user',
]

# ===============================================================
# 🔧 DRF CONFIG
# ===============================================================
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),

    # Browsable API errors solved (CSS/JS loading)
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    ],
}

# ===============================================================
# 🧱 MIDDLEWARE (WhiteNoise added)
# ===============================================================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',

    # MUST for Render Static Files
    'whitenoise.middleware.WhiteNoiseMiddleware',

    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

# ===============================================================
# 🖥️ TEMPLATES
# ===============================================================
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# ===============================================================
# 🗃 DATABASE
# ===============================================================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT'),
    }
}

# ===============================================================
# 🔐 PASSWORD RULES
# ===============================================================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ===============================================================
# 🌐 INTERNATIONALIZATION
# ===============================================================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# ===============================================================
# 📁 STATIC & MEDIA FILES (Render Ready)
# ===============================================================
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")

# Local static folder (optional)
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

# WhiteNoise storage optimization
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# ===============================================================
# 📦 UPLOAD LIMITS
# ===============================================================
DATA_UPLOAD_MAX_MEMORY_SIZE = 52428800
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800

# ===============================================================
# 🔑 JWT CONFIG
# ===============================================================
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
}

# ===============================================================
# 🪵 LOGGING
# ===============================================================
if DEBUG:
    LOGGING_DIR = os.path.join(BASE_DIR, "log")

    os.makedirs(os.path.join(LOGGING_DIR, "debug_logs"), exist_ok=True)
    os.makedirs(os.path.join(LOGGING_DIR, "info_logs"), exist_ok=True)
    os.makedirs(os.path.join(LOGGING_DIR, "warning_logs"), exist_ok=True)
    os.makedirs(os.path.join(LOGGING_DIR, "error_logs"), exist_ok=True)
    os.makedirs(os.path.join(LOGGING_DIR, "critical_logs"), exist_ok=True)

    LOGGING = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            },
        },
        "handlers": {
            "debug": {
                "level": "DEBUG",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": os.path.join(LOGGING_DIR, "debug_logs/debug.log"),
                "backupCount": 10,
                "maxBytes": 5 * 1024 * 1024,
                "formatter": "standard",
            },
            "info": {
                "level": "INFO",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": os.path.join(LOGGING_DIR, "info_logs/info.log"),
                "backupCount": 10,
                "maxBytes": 5 * 1024 * 1024,
                "formatter": "standard",
            },
            "warning": {
                "level": "WARNING",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": os.path.join(LOGGING_DIR, "warning_logs/warning.log"),
                "backupCount": 10,
                "maxBytes": 5 * 1024 * 1024,
                "formatter": "standard",
            },
            "error": {
                "level": "ERROR",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": os.path.join(LOGGING_DIR, "error_logs/error.log"),
                "backupCount": 10,
                "maxBytes": 5 * 1024 * 1024,
                "formatter": "standard",
            },
            "critical": {
                "level": "CRITICAL",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": os.path.join(LOGGING_DIR, "critical_logs/critical.log"),
                "backupCount": 10,
                "maxBytes": 5 * 1024 * 1024,
                "formatter": "standard",
            },
        },
        "loggers": {
            "django": {
                "handlers": ["debug", "info", "warning", "error", "critical"],
                "level": "DEBUG",
                "propagate": False,
            },
        },
    }

else:
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
            },
        },
        'root': {
            'handlers': ['console'],
            'level': 'INFO',
        },
    }
