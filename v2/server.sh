#!/bin/bash
INSTALL="0"
cd $(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
command python3 --version >/dev/null 2>&1 || {
    echo python3 not found in path
    exit 1;
}

if [ ! -f ./.venv/bin/activate ]; then
    if [ -e ./.venv ]; then
        rm -rf ./.venv
    fi
    python3 -m venv .venv
fi

set -e
source .venv/bin/activate

if [ "$INSTALL" == "1" ]; then
    pip install pip --upgrade
    pip install async colorclass pyopenssl werkzeug halo async_timeout jinja2 cryptography \
        psutil aiodns ujson msgpack pendulum aiohttp-sse pyte colorlog jsonlog \
        aiohttp_session aiomysql aiocache aiohttp aiohttp_jwt aiohttp_session[secure] aiohttp-jinja2
    pip freeze
fi
clear
exec python3 _server.py 2>&1
