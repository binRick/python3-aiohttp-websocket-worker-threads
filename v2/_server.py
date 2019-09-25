import os, sys, json, time, subprocess, base64, ssl, pprint, socket, traceback, asyncio, aiohttp.web, logging, jwt, OpenSSL, threading, halo, colorclass, jinja2, aiohttp_jinja2, aiomysql, psutil, aiodns, pyte, pathlib, signal, shlex, pty
from aiohttp_sse import sse_response
from datetime import datetime
from aiocache import cached, Cache
from aiocache.serializers import PickleSerializer
from collections import namedtuple
from cryptography import fernet
from aiohttp import web
from aiohttp_jwt import JWTMiddleware, check_permissions, match_any
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage

_DEBUG_WEBSERVER_REQUESTS = True
_DEBUG_WEBSERVER_RESPONSES = True
_DEBUG_VERBOSE = True
sharable_secret = 'secret'

logging.basicConfig(level=logging.DEBUG)
THREAD_INTERVAL = 5.0
CHECK_WEBSOCKETS_INTERVAL = 5.0
HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 50009))
STATIC_PATH = "{}/static".format(os.path.dirname(os.path.realpath(__file__)))
TEMPLATE_PATH = "{}/templates".format(os.path.dirname(os.path.realpath(__file__)))
thisProcess = psutil.Process()

WEBSOCKET_PUBLISH_TYPES = {
  "backgroundProcessorEvents": set(),
}
WEBSOCKET_SUBSCRIPTIONS = {
  "openconnect": set(),
  "openvpn": set(),
  "wireguard": set(),
  "backgroundProcessorEvents": set(),
}
SUBSCRIPTION_THREAD_CLASSES = {
  "openconnect": 'MonitorOpenconnectClientThread',
  "openvpn": 'MonitorOpenVPNClientThread',
  "wireguard": 'MonitorWireguardClientThread',
  "backgroundProcessorEvents": 'BackgroundProcessorEventsThread',
}

def initApp():
    app = web.Application(
        middlewares=[
            JWTMiddleware(
                secret_or_pub_key=sharable_secret,
                token_getter=get_token,
                request_property='user',
                credentials_required=False,
                whitelist=[
                    r'/public*'
                ]
            )
        ]
    )
    fernet_key = fernet.Fernet.generate_key()
    secret_key = base64.urlsafe_b64decode(fernet_key)
    setup(app, EncryptedCookieStorage(secret_key))
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(TEMPLATE_PATH))
    return app


def initPerms():
    @check_permissions([
        'app/user:admin',
        'username:olehkuchuk',
    ], comparison=match_any)
    async def protected_handler(request):
        return web.json_response({
            'username': request['user'].get('username'),
        })

async def sse_html_handler(request):
    d = """
        <html>
        <body>
            <script>
                var evtSource = new EventSource("/tests/sse/data");
                evtSource.onmessage = function(e) {
                    document.getElementById('response').innerText = e.data
                }
            </script>
            <h1>Response from server:</h1>
            <div id="response"></div>
        </body>
    </html>
    """
    return aiohttp.web.Response(text=d, content_type='text/html')

async def sse_data_handler(request):
    async with sse_response(request) as resp:
        while True:
            data = 'Server Time : {}'.format(datetime.now())
            print(data)
            await resp.send(data)
            await asyncio.sleep(1, loop=request.app.loop)
    return resp

async def jinja_handler(request):
    session = await get_session(request)
    last_visit = session['last_visit'] if 'last_visit' in session else None
    session['last_visit'] = time.time()
    text = 'Last visited: {}'.format(last_visit)
    context = {'name': 'Andrew', 'surname': 'Svetlov', 'last_visit': last_visit}
    response = aiohttp_jinja2.render_template('index.html.j2',request,context)
    response.headers['Content-Language'] = 'ru'
    return response

async def cached_handler_set(request):
    server_id = int(request.match_info['server_id'])
    await request.app["cache"].set("server_id", server_id)
    return aiohttp.web.Response(text='Cache Set!')

async def cached_handler_get(request):
    server_id = await request.app["cache"].get("server_id")
    return aiohttp.web.Response(text='Cache={}'.format(server_id))
    
async def cached_handler(request):
    await request.app["cache"].set("key", "value")
    return aiohttp.web.Response(text='Test handle')
    

async def protected_handler(request):
    return web.json_response({'user': request['payload']})

async def sleep_handler(request):
    await asyncio.sleep(2)


async def test(name):
    print(f'Begin:{name} {pendulum.now()}')
    await asyncio.sleep(2)
    print(f'End:{name} {pendulum.now()}')

async def task_handler():
    task1 = asyncio.create_task(test('A'))
    task2 = asyncio.create_task(test('B'))
    await task1
    await task2

async def sql_handler(request):
    conn = await aiomysql.connect(host='127.0.0.1', port=3306,user='root', password='', db='mysql',loop=request.app.loop)
    async with conn.cursor(aiomysql.cursors.DeserializationCursor,aiomysql.cursors.DictCursor) as cur:
        await cur.execute("SELECT Host,User FROM user")
        #print(cur.description)
        r = await cur.fetchall()
        #print(r)
    conn.close()
    return web.json_response({'user': "wow", "sqlResult": r})


async def public_handler(request):
    return web.json_response({
        'username': request['user'].get('username')
        if 'user' in request else 'anonymous',
    })



async def get_token(request):
    return jwt.encode({
        'username': 'olehkuchuk',
        'scopes': ['username:olehkuchuk'],
    }, sharable_secret)


"""   Monitor Websockets and Subscriptions """
class CheckWebsocketsThread(threading.Thread):
    def __init__(self, event, INTERVAL, app):
        threading.Thread.__init__(self)
        self.stopped = event
        self.INTERVAL = INTERVAL
        self.app = app
    def run(self):
        while not self.stopped.wait(self.INTERVAL):
            logging.debug("  {} WEBSOCKET CONNECTIONS".format(len(self.app['websockets'])))
            if len(self.app['websockets']) > 0:
             for s in WEBSOCKET_SUBSCRIPTIONS.keys():
              logging.debug("        {} {}/{} Subscriptions".format(s, len(self.app['subscriptions'][s]), int(MAX_SUBSCRIPTIONS)))

async def api_handler1(request):
    session = await get_session(request)
    server_id = int(request.match_info['server_id'])
    last_visit = session['last_visit'] if 'last_visit' in session else None
    context = {'name': 'Andrew', 'surname': 'Svetlov', 'last_visit': last_visit, 'server_id': server_id,}
    session['last_visit'] = time.time()
    response = aiohttp_jinja2.render_template('index.html.j2',request,context)
    return response


async def testhandle(request):
    session = await get_session(request)
    last_visit = session['last_visit'] if 'last_visit' in session else None
    session['last_visit'] = time.time()
    text = 'Last visited: {}'.format(last_visit)
    return aiohttp.web.Response(text='Test handle')


async def websocket_handler(request):
    logging.debug('Websocket connection starting')
    if VERBOSE_DEBUG:
      logging.debug("method={},host={},path={},headers={},transport={},cookies={}".format(
                  request.method,
                  request.host,
                  request.path,
                  request.headers,
                  request.transport,
                  request.cookies,
                ))
    clientIP = request.headers['X-Forwarded-For']
    logging.debug("Client Request from {} with headers {}".format(clientIP, request.headers.keys()))
    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)
    request.app["websockets"].add(ws)
    logging.debug('Websocket connection ready')

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == 'close':
                await ws.close()
            else:
                try:
                  clientResponseText = ''
                  message = msg.json()

                  if 'subscribe' in message.keys():
                    logging.debug("Subscription Request: {}".format(message))


                except (TypeError, ValueError):
                  message = msg.data
                resp = "{}".format(message) + ' => {}'.format(clientResponseText)
                ws.send_str(resp)
                message = msg.data


    logging.debug('Websocket connection closed')
    request.app["websockets"].remove(ws)
    for s in request.app['subscriptions'].keys():
      if ws in request.app['subscriptions'][s]:
        request.app['subscriptions'][s].remove(ws)
        if len(request.app['subscriptions'][s]) == 0 and request.app['clientThreads'][s].is_alive():
          logging.debug("Stopping Thread {}".format(s))
          try:
            request.app['clientThreadStops'][s].set()
          except Exception as e:
            logging.debug("   Failed to stop Thread {}: {}".format(s, e))
    return ws

def initThreads(app):
    app['threadStops']['checkWebsockets'] = threading.Event()
    app['threads']['checkWebsockets'] = CheckWebsocketsThread(app['threadStops']['checkWebsockets'], CHECK_WEBSOCKETS_INTERVAL, app)
    app['threads']['checkWebsockets'].daemon = True
    app['threads']['checkWebsockets'].start()

def initRoutes(app):
    app.router.add_static('/static/', path=STATIC_PATH, name='static')
    app.router.add_route('GET', '/', testhandle)
    app.router.add_route('GET', '/ws', websocket_handler)
    app.router.add_route('GET', '/public', public_handler)
    app.router.add_route('GET', '/templateTest', jinja_handler)
    app.router.add_route('GET', '/protected', protected_handler)
    app.router.add_route('GET', '/tests/cached', cached_handler)
    app.router.add_route('GET', '/tests/sql', sql_handler)
    app.router.add_route('GET', '/tests/sse/data', sse_data_handler)
    app.router.add_route('GET', '/tests/sse', sse_html_handler)
    app.router.add_route('GET', '/api/server/{server_id}', api_handler1)
    app.router.add_route('GET', '/api/cache/set/server_id/{server_id}', cached_handler_set)
    app.router.add_route('GET', '/api/cache/get/server_id', cached_handler_get)

def initAppObjects(app):
    app["cache"] = Cache(Cache.MEMORY)
    app["websockets"] = set()
    app["threads"] = {}
    app["clientThreads"] = {}
    app["subscriptions"] = WEBSOCKET_SUBSCRIPTIONS
    app["publishTypes"] = WEBSOCKET_PUBLISH_TYPES
    app["threadStops"] = {}
    app["clientThreadStops"] = {}

def main():
    loop = asyncio.get_event_loop()
    resolver = aiodns.DNSResolver(loop=loop)
    app = initApp()
    initPerms()
    initAppObjects(app)

    initRoutes(app)
    initThreads(app)

    aiohttp.web.run_app(app, host=HOST, port=PORT)

if __name__ == '__main__':
    main()





