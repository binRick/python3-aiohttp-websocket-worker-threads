#!/bin/bash
set -e
cd $(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )


source ./.venv/bin/activate
INSTALL="1"

if [ "$INSTALL" == "1" ]; then
    pip install async colorclass pyopenssl werkzeug halo async_timeout jinja2 cryptography \
        psutil aiodns ujson msgpack pendulum aiohttp-sse pyte \
        aiohttp_session aiomysql aiocache aiohttp aiohttp_jwt "aiohttp_session[secure]" aiohttp-jinja2
    pip freeze
fi

exec python3 _server.py 2>&1
