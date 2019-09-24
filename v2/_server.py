import os, sys, json, time, subprocess, base64, ssl, pprint, socket, traceback, asyncio, aiohttp.web, logging, jwt, OpenSSL, threading, halo, colorclass, jinja2, aiohttp_jinja2, aiomysql, psutil, aiodns, pyte, pathlib, signal, shlex, pty, select, colorlog, jsonlog
from colorlog import ColoredFormatter
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


jsonlog.basicConfig(
    level=jsonlog.INFO,
    indent=None,
    keys=("timestamp", "level", "message"),
    timespec="auto",
    #filename="{}/{}".format(os.path.realpath(os.path.dirname(os.path.abspath(__file__))),'access.log'),
    # filemode="a",
    # stream=None,
)

logging.warning("User clicked a button", extra={"user": 123})

"""
TRACE = 5
logging.addLevelName(TRACE, 'TRACE')
formatter = colorlog.ColoredFormatter(log_colors={'TRACE': 'yellow'})

logger.setLevel('TRACE')
logger.log(TRACE, 'a message using a custom level')
logger = logging.getLogger('example')
logger.addHandler(handler)
logger.setLevel('TRACE')
logger.log(TRACE, 'a message using a custom level')
"""

"""
logging.basicConfig(level=logging.DEBUG)
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
	'%(log_color)s%(levelname)s:%(name)s:%(message)s'))

formatter = ColoredFormatter(
	"%(log_color)s%(levelname)-8s%(reset)s %(blue)s%(message)s",
	datefmt=None,
	reset=True,
	log_colors={
		'DEBUG':    'cyan',
		'INFO':     'green',
		'WARNING':  'yellow',
		'ERROR':    'red',
		'CRITICAL': 'red,bg_white',
	},
	secondary_log_colors={},
	style='%'
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger = colorlog.getLogger('example')
logger.addHandler(handler)
logger.log(0, 'a message using a custom level')
"""


MAX_SUBSCRIPTIONS = 10
SHARABLE_SECRET = 'xxxxxxxxxxxxxxxxxxxx'
THREAD_INTERVAL = 5.0
CHECK_WEBSOCKETS_INTERVAL = 10.0
HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 50009))
STATIC_PATH = "{}/static".format(os.path.dirname(os.path.realpath(__file__)))
TEMPLATE_PATH = "{}/templates".format(os.path.dirname(os.path.realpath(__file__)))
THIS_PROCESS = psutil.Process()
IS_SHUTTING_DOWN = False

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


class Terminal:
    def __init__(self, columns, lines, p_in):
        self.screen = pyte.HistoryScreen(columns, lines)
        self.screen.set_mode(pyte.modes.LNM)
        self.screen.write_process_input = \
            lambda data: p_in.write(data.encode())
        self.stream = pyte.ByteStream()
        self.stream.attach(self.screen)

    def feed(self, data):
        self.stream.feed(data)

    def dumps(self):
        cursor = self.screen.cursor
        lines = []
        for y in self.screen.dirty:
            line = self.screen.buffer[y]
            data = [(char.data, char.reverse, char.fg, char.bg)
                    for char in (line[x] for x in range(self.screen.columns))]
            lines.append((y, data))

        self.screen.dirty.clear()
        print("returning {} lines".format(len(lines)))
        return json.dumps({"c": (cursor.x, cursor.y), "lines": lines})




def open_terminal(command="bash", columns=80, lines=24):
    p_pid, master_fd = pty.fork()
    if p_pid == 0:  # Child.
        argv = shlex.split(command)
        env = dict(TERM="linux", LC_ALL="en_GB.UTF-8",COLUMNS=str(columns), LINES=str(lines))
        os.execvpe(argv[0], argv, env)

    # File-like object for I/O with the child process aka command.
    p_out = os.fdopen(master_fd, "w+b", 0)
    return Terminal(columns, lines, p_out), p_pid, p_out





async def on_shutdown(app):
    """Closes all WS connections on shutdown."""
    global IS_SHUTTING_DOWN
    IS_SHUTTING_DOWN = True
    for task in app["websockets"]:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


logging.warning("[cached_handler_get]",extra={"server_id": 123})


def initApp():
    app = web.Application(
        middlewares=[
            JWTMiddleware(
                secret_or_pub_key=SHARABLE_SECRET,
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


def initPerms(app):
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
            await resp.send(data)
            await asyncio.sleep(1, loop=request.app.loop)
    return resp

async def jinja_handler(request):
    session = await get_session(request)
    last_visit = session['last_visit'] if 'last_visit' in session else None
    session['last_visit'] = time.time()
    context = {'name': 'Andrew', 'surname': 'Svetlov', 'last_visit': last_visit}
    response = aiohttp_jinja2.render_template('index.html.j2',request,context)
    response.headers['Content-Language'] = 'ru'
    return response

async def cached_handler_set(request):
    logging.warning("User clicked a button", extra={"user": 123})
    server_id = int(request.match_info['server_id'])
    await request.app["cache"].set("server_id", server_id)
    return aiohttp.web.Response(text='Cache Set!')

async def cached_handler_get(request):
    server_id = await request.app["cache"].get("server_id")
    logging.warning("[cached_handler_get]",extra={"server_id": server_id})
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
    }, SHARABLE_SECRET)


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
    return aiohttp.web.Response(text='Test handle')

async def websocket_handler_terminal(request):
    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)
    request.app["websockets"].add(ws)

    terminal, p_pid, p_out = open_terminal()
    #ws.send_str(terminal.dumps())

    def on_master_output():
        terminal.feed(p_out.read(65536))
        tout = terminal.dumps()
        print("sending {} bytes of output: {}".format(len(tout), tout))
        #ws.send_str(tout)
        #request.app.loop.call_soon(ws.send_str, tout)

    request.app.loop.add_reader(p_out, on_master_output)
    try:
        async for msg in ws:
            print("{} byte msg: {}".format(len(msg), msg))
            if msg.type == aiohttp.WSMsgType.TEXT:
                if msg.data == pyte.control.ESC + "N":
                    terminal.screen.next_page()
                    await ws.send_str(terminal.dumps())
                elif msg.data == pyte.control.ESC + "P":
                    terminal.screen.prev_page()
                    await ws.send_str(terminal.dumps())
                else:
                    _in = msg.data.encode()
                    print("writing {}".format(_in))
                    p_out.write(_in)
            elif msg.type == aiohttp.WSMsgType.ERROR:
                raise ws.exception()
    except (asyncio.CancelledError, OSError):
        pass
    finally:
        request.app.loop.remove_reader(p_out)
        os.kill(p_pid, signal.SIGTERM)
        p_out.close()
        if not IS_SHUTTING_DOWN:
            request.app["websockets"].remove(asyncio.Task.current_task())
    await ws.close()
    return ws


async def websocket_handler_basic(request):
    logging.debug('Websocket connection starting')
    if _DEBUG_VERBOSE:
      logging.debug("method={},host={},path={},headers={},transport={},cookies={}".format(
                  request.method,
                  request.host,
                  request.path,
                  request.headers,
                  request.transport,
                  request.cookies,
                ))

    peername = request.transport.get_extra_info('peername')
    client_host, client_port = peername
    try:
        clientIP = request.headers['X-Forwarded-For']
    except Exception as e:
        clientIP = client_host

    logging.debug("Client Request from {} with headers {}".format(clientIP, request.headers.keys()))
    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)
    request.app["websockets"].add(ws)
    logging.debug('Websocket connection ready')
    terminal, p_pid, p_out = open_terminal()
    #await ws.send_str(terminal.dumps())
    def on_master_output():
        terminal.feed(p_out.read(65536))
        tout = terminal.dumps()
        print("sending {} bytes of output: {}".format(len(tout), tout))
        ws.send_str(tout)
        #request.app.loop.call_soon(ws.send_str, tout)
    request.app.loop.add_reader(p_out, on_master_output)

    async for msg in ws:
        print("{} byte msg: {}".format(len(msg), msg))
        if msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == 'close':
                await ws.close()
            else:
                try:
                  clientResponseText = ''
                  message = msg.json()
                  print("{} byte message: {}".format(len(message), message))
                  if 'subscribe' in message.keys():
                    logging.debug("Subscription Request: {}".format(message))

                  _in = msg.data.encode()
                  print("writing {}".format(_in))
                  p_out.write(_in)


                except (TypeError, ValueError):
                  message = msg.data

                """
                resp = "{}".format(message) + ' => {}'.format(clientResponseText)
                await ws.send_str(resp)
                await ws.send_str(terminal.dumps())
                message = msg.data
                """


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
    app.router.add_route('GET', '/public', public_handler)
    app.router.add_route('GET', '/templateTest', jinja_handler)
    app.router.add_route('GET', '/protected', protected_handler)
    app.router.add_route('GET', '/tests/one', testhandle)
    app.router.add_route('GET', '/tests/cached', cached_handler)
    app.router.add_route('GET', '/tests/sql', sql_handler)
    app.router.add_route('GET', '/tests/sse/data', sse_data_handler)
    app.router.add_route('GET', '/tests/sse', sse_html_handler)
    app.router.add_route('GET', '/api/server/{server_id}', api_handler1)
    app.router.add_route('GET', '/tests/cache/set/server_id/{server_id}', cached_handler_set)
    app.router.add_route('GET', '/tests/cache/get/server_id', cached_handler_get)
    app.router.add_route('GET', '/ws/basic', websocket_handler_basic)
    app.router.add_route('GET', '/ws/terminal', websocket_handler_terminal)
    app.router.add_static("/", "{}/static".format(pathlib.Path(__file__).parent), show_index=True)

def initAppObjects(app):
    app["cache"] = Cache(Cache.MEMORY)
    app["resolver"] = aiodns.DNSResolver(app.loop)
    app["websockets"] = set()
    app["subscriptions"] = WEBSOCKET_SUBSCRIPTIONS
    app["publishTypes"] = WEBSOCKET_PUBLISH_TYPES
    app["threads"] = {}
    app["clientThreads"] = {}
    app["threadStops"] = {}
    app["clientThreadStops"] = {}

def initCleanups(app):
    app.on_shutdown.append(on_shutdown)


def main():
    app = initApp()
    initPerms(app)
    initAppObjects(app)
    initRoutes(app)
    initThreads(app)
    initCleanups(app)

    try:
        aiohttp.web.run_app(app, host=HOST, port=PORT)
    except Exception as e:
        print(e)
        sys.exit(1)

if __name__ == '__main__':
    main()





