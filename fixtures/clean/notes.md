# Deployment notes

The binary lives at /usr/local/bin/app-server and is symlinked into PATH.
See https://docs.example.com/guides/getting-started-with-secrets for details.

Configuration is read from `config.json`. The request id is a UUID such as
550e8400-e29b-41d4-a716-446655440000 and rotates every hour.

    timeout = 30
    retries = 3
    metadata-version = 2.1
