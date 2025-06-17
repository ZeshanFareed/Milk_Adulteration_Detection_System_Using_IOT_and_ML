import os
from pathlib import Path

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: Replace this in production
SECRET_KEY = 'xtWxuLmpN9hsb7q2B9gVIdC1pETnxbHlIFDwrtBV'

# Debug mode for development
DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'MADS.middleware.FirebaseAuthMiddleware',
    'django.middleware.locale.LocaleMiddleware',
]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'MADS',
    
]

ROOT_URLCONF = 'MADS.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'template')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.i18n',
            ],
        },
    },
]

# Use dummy database since we're using Firebase
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.dummy',
    }
}


LANGUAGE_CODE = 'en'  # Default language
LANGUAGES = [
    ('en', 'English'),
    ('ur', 'Urdu'),
]

# Session configuration (use cache-based backend)
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

WSGI_APPLICATION = 'MADS.wsgi.application'

# Firebase configuration
FIREBASE_CONFIG = {
    'apiKey': "AIzaSyD9bdbuPfSJCZBweGNDd8m7Hy_R09RGwH8",
    'authDomain': "mads-36618.firebaseapp.com",
    'databaseURL': "https://mads-36618-default-rtdb.europe-west1.firebasedatabase.app",
    'projectId': "mads-36618",
    'storageBucket': "mads-36618.firebasestorage.app",
    'messagingSenderId': "241911821511",
    'appId': "1:241911821511:web:a8b0ee4c97be51c62c7ae2"
}

# Path to Firebase Admin SDK credentials
FIREBASE_CREDENTIALS = os.path.join(BASE_DIR, r'C:\Users\PMLS\Documents\MADS\MADS\MADS\mads-36618-firebase-adminsdk-fbsvc-36d1a4f592.json')

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LOCALE_PATHS = [
    os.path.join(BASE_DIR, 'locale'),
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Authentication settings
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'login'

# Email settings (for password reset)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Custom settings
MADS_CONFIG = {
    'SENSOR_UPDATE_INTERVAL': 3000,
    'MAX_HISTORICAL_DATA': 100,
}

# User roles configuration
USER_ROLES = {
    'admin': ['dashboard', 'reports', 'user_management', 'settings', 'help'],
    'qc': ['dashboard', 'reports', 'help'],
    'user': ['dashboard', 'help']
}

# Logging for debugging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'debug.log'),
            'formatter': 'verbose',
        },
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}