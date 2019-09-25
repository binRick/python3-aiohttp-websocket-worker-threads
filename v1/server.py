#!/usr/bin/env python3.6
import asyncio, os, aiohttp.web, logging, sys, json, threading, inspect
from aiohttp import web


logging.basicConfig(level=logging.DEBUG)

HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 9999))
STATIC_PATH = os.path.dirname(sys.argv[0])+'/static'
VERBOSE_DEBUG = False

WEBSOCKET_SUBSCRIPTIONS = {
  "openconnect": set(),
  "openvpn": set(),
  "wireguard": set(),
}
SUBSCRIPTION_THREAD_CLASSES = {
  "openconnect": 'MonitorOpenconnectClientThread',
  "openvpn": 'MonitorOpenVPNClientThread',
  "wireguard": 'MonitorWireguardClientThread',
}


def get_classes():
    classes = {}
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            classes[name] = obj
    return classes

class MonitorOpenconnectClientThread(threading.Thread):
    def __init__(self, event, INTERVAL, app):
        threading.Thread.__init__(self)
        self.stopped = event
        self.INTERVAL = INTERVAL
        self.app = app
    def run(self):
        while not self.stopped.wait(self.INTERVAL):
            logging.debug("  MonitorOpenconnectClientThread")

class MonitorWireguardClientThread(threading.Thread):
    def __init__(self, event, INTERVAL, app):
        threading.Thread.__init__(self)
        self.stopped = event
        self.INTERVAL = INTERVAL
        self.app = app
    def run(self):
        while not self.stopped.wait(self.INTERVAL):
            logging.debug("  MonitorWireguardClientThread")

class MonitorOpenVPNClientThread(threading.Thread):
    def __init__(self, event, INTERVAL, app):
        threading.Thread.__init__(self)
        self.stopped = event
        self.INTERVAL = INTERVAL
        self.app = app
    def run(self):
        while not self.stopped.wait(self.INTERVAL):
            logging.debug("  MonitorOpenVPNClientThread")

class CheckWebsocketsThread(threading.Thread):
    def __init__(self, event, INTERVAL, app):
        threading.Thread.__init__(self)
        self.stopped = event
        self.INTERVAL = INTERVAL
        self.app = app
    def run(self):
        while not self.stopped.wait(self.INTERVAL):
            classes = get_classes()
            logging.debug("  {} Classes: {}".format(len(classes), classes))
            logging.debug("  {} WEBSOCKET CONNECTIONS".format(len(self.app['websockets'])))
            if len(self.app['websockets']) > 0:
             for s in WEBSOCKET_SUBSCRIPTIONS.keys():
              logging.debug("        {} {} Subscriptions".format(s, len(self.app['subscriptions'][s])))

async def testhandle(request):
    return aiohttp.web.Response(text='Test handle')

async def websocket_handler(request):
    logging.debug('Websocket connection starting')
    if VERBOSE_DEBUG:
      logging.debug(
                "method={},host={},path={},headers={},transport={},cookies={}"
                .format(
                  request.method,
                  request.host,
                  request.path,
                  request.headers,
                  request.transport,
                  request.cookies,
                ))
    clientIP = request.headers['X-Forwarded-For']
    logging.debug("Client Request from {}".format(clientIP))  
    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)
    request.app["websockets"].add(ws)
    logging.debug('Websocket connection ready')

    async for msg in ws:
        #logging.debug(msg)
        if msg.type == aiohttp.WSMsgType.TEXT:
            if msg.data == 'close':
                await ws.close()
            else:
                try:
                  message = msg.json()
                  if 'subscribe' in message.keys():
                    logging.debug("Subscription Request: {}".format(message))
                    if message['subscribe'] in request.app['subscriptions'].keys():
                      if not ws in request.app['subscriptions'][message['subscribe']]:
                        request.app['subscriptions'][message['subscribe']].add(ws)
                        if message['subscribe'] in SUBSCRIPTION_THREAD_CLASSES.keys():
                          logging.debug("Checking Thread {} :: {}".format(message['subscribe'], SUBSCRIPTION_THREAD_CLASSES[message['subscribe']]))
                          if message['subscribe'] in request.app['clientThreads'].keys() and request.app['clientThreads'][message['subscribe']].is_alive():
                            logging.debug("  Alive")
                          else:
                            logging.debug("  Dead")
                            try:
                              request.app['clientThreadStops'][message['subscribe']] = threading.Event()
                              #mc = get_classes[SUBSCRIPTION_THREAD_CLASSES[message['subscribe']]]
                              mc = globals()[SUBSCRIPTION_THREAD_CLASSES[message['subscribe']]]
                              request.app['clientThreads'][message['subscribe']] = mc(request.app['clientThreadStops'][message['subscribe']], 2.0, request.app)
                              request.app['clientThreads'][message['subscribe']].daemon = True
                              request.app['clientThreads'][message['subscribe']].start()
                            except Exception as e:
                              logging.debug("**FAILED TO START THREAD {}**".format(message['subscribe']))
                              logging.debug(e)


                except (TypeError, ValueError):
                  message = msg.data
                resp = "{}".format(message) + ' => /answer'
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


def main():
    loop = asyncio.get_event_loop()
    app = aiohttp.web.Application(loop=loop)
    app["websockets"] = set()
    app["threads"] = {}
    app["clientThreads"] = {}
    app["threadStops"] = {}
    app["clientThreadStops"] = {}
    app["clientThreadStarts"] = {}
    app["subscriptions"] = WEBSOCKET_SUBSCRIPTIONS
    app.router.add_static('/static/', path=STATIC_PATH, name='static')
    app.router.add_route('GET', '/', testhandle)
    app.router.add_route('GET', '/ws', websocket_handler)

    app['threadStops']['checkWebsockets'] = threading.Event()
    app['threads']['checkWebsockets'] = CheckWebsocketsThread(app['threadStops']['checkWebsockets'], 2.0, app)
    app['threads']['checkWebsockets'].daemon = True
    app['threads']['checkWebsockets'].start()

    aiohttp.web.run_app(app, host=HOST, port=PORT)

if __name__ == '__main__':
    main()
