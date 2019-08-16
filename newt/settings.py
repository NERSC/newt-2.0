# Django settings for newt project.
import os

DEBUG = True
TEMPLATE_DEBUG = DEBUG
PROJECT_DIR = os.path.dirname(os.path.dirname(__file__))

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)

MANAGERS = ADMINS

DATABASES = {
    'default': {
        'TEST_NAME': 'test_sqlite.db',
        'ENGINE': 'django.db.backends.sqlite3',  # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': 'newtdb.sqlite',                      # Or path to database file if using sqlite3.
        # The following settings are not used with sqlite3:
        'USER': '',
        'PASSWORD': '',
        'HOST': '',                      # Empty for localhost through domain sockets or '127.0.0.1' for localhost through TCP.
        'PORT': '',                      # Set to empty string for default.
    }
}


# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'America/Los_Angeles'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = ''

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    #    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

# Make this unique, and don't share it with anybody.
SECRET_KEY = 't#xa0x&s*^0892&nmspv+sdrf9)rj@$w$n(2vf!n#dorv@oupy'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
    #     'django.template.loaders.eggs.Loader',
)

MIDDLEWARE = (
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django_json_404_middleware.JSON404Middleware',
    # Uncomment the next line for simple clickjacking protection:
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
)


CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_METHODS = ( 'POST', 'GET', 'OPTIONS', 'PUT', 'DELETE', 'HEAD', )

ALLOWED_HOSTS = ['0.0.0.0', 'newt-2.newt-2.dev-cattle.stable.spin.nersc.org', '127.0.0.1']

ROOT_URLCONF = 'newt.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'newt.wsgi.application'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'newt',
    'authnz',
    'status',
    'file',
    'store',
    'account',
    'job',
    'corsheaders',
    # Uncomment the next line to enable the admin:
    'django.contrib.admin',
    # Uncomment the next line to enable admin documentation:
    'django.contrib.admindocs',
)

AUTHENTICATION_BACKENDS = (
    # 'django.contrib.auth.backends.ModelBackend',
    'authnz.adapters.sshapi_backend.SSHAPIBackend',
)


# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
if DEBUG:
    _LOGDIR = PROJECT_DIR
else:
    _LOGDIR = "/var/log/httpd/"
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'full': {
            'format': '[%(levelname)s] %(asctime)s %(name)s : %(message)s'
        },
        'brief': {
            'format': '[%(levelname)s] %(message)s'
        },
        'message_only': {
            'format': '%(message)s'
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler'
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'full'
        },
        'logfile': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(_LOGDIR, 'django.log'),
            'formatter': 'full',
            'maxBytes': 1000000,
            'backupCount': 3
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins', 'logfile'],
            'level': 'ERROR',
            'propagate': True,
        },
        'newt': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': True,
        },
    }
}

# Base NEWT Settings
NEWT_VERSION = '2.0.0'
NEWT_HOST = 'localhost'
NEWT_DOMAIN = 'nersc.gov'
NEWT_COOKIE_LIFETIME = 43200
MYPROXY_SERVER = 'nerscca2.nersc.gov'
SSHPROXY_SERVER = 'https://sshproxy.nersc.gov/create_pair/default/'
SSH_CMD = 'ssh'
# SESSION_COOKIE_DOMAIN = NEWT_HOST
# SESSION_COOKIE_SECURE = True
SESSION_COOKIE_NAME = 'newt_sessionid'
CSRF_COOKIE_DOMAIN = NEWT_HOST
CSRF_COOKIE_NAME = 'newt_sessionid'

NEWT_CONFIG = {
    'SYSTEMS': [
        {'NAME': 'cori', 'HOSTNAME': 'cori.nersc.gov'},
    ],
    'ADAPTERS': {
        'STATUS': {
            'adapter': 'status.adapters.ping_adapter',
            'models': '',
        },
        'FILE': {
            'adapter': 'file.adapters.localfile_adapter',
            'models': "",
        },
        'AUTH': {
            # 'adapter': 'authnz.adapters.dbauth_adapter',
            'adapter': 'authnz.adapters.sshapi_adapter',
            'models': '',
        },
        'COMMAND': {
            'adapter': 'command.adapters.ssh_exec_adapter',
            'models': '',
        },
        'STORES': {
            'adapter': 'store.adapters.dbstore_adapter',
            'models': 'store.adapters.dbstore_models',
        },
        'ACCOUNT': {
            'adapter': 'account.adapters.django_adapter',
            'models': '',
        },
        'JOB': {
            'adapter': 'job.adapters.unix_adapter',
            'models': '',
        },
    },
}

try:
    from local_settings import *
except ImportError:
    pass
