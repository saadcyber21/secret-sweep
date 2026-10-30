"""A deliberately boring module. Scanning it must produce zero findings."""
import json
import os

DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3


def load_config(path="config.json"):
    with open(path) as fh:
        return json.load(fh)


def connection_string(host, port, database):
    return f"postgresql://{host}:{port}/{database}"


class ConfigManager:
    def __init__(self, environment="development"):
        self.environment = environment
        self.ssl_handshake_timeout = DEFAULT_TIMEOUT

    def resolve(self, name):
        return os.environ.get(name, "")
