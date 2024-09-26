import os
import builtins
import logging
import os
import sys
from collections import OrderedDict

class Config:
    SECRET_KEY = os.urandom(32)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # We need to include the root directory in sys.path to ensure that we can
    # find everything we need when running in the standalone runtime.
    root = os.path.dirname(os.path.realpath(__file__))
    if sys.path[0] != root:
        sys.path.insert(0, root)

    # The config database connection pool size.
    # Setting this to 0 will remove any limit.
    CONFIG_DATABASE_CONNECTION_POOL_SIZE = 5
    # The number of connections allowed to overflow beyond
    # the connection pool size.
    CONFIG_DATABASE_CONNECTION_MAX_OVERFLOW = 100
