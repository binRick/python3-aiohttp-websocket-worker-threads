$(document).ready(function() {
    var vpnServerSocketConnection = function(serverID, serverHostname, openCallback, messageCallback) {
        generateVpnServiceWebsocketToken(serverID, function(wt) {
            l('token=', wt);
            var wsServer = 'wss://' + serverHostname,
                uri = '/vpnServiceWebsocketServer/ws?token=' + wt.data;
            var _URL = wsServer + uri;
            l('URL=', _URL);
            const socket = new WebSocket(_URL);
            socket.addEventListener('open', function() {
                openCallback(socket);
            });
            socket.addEventListener('message', function(event) {
                messageCallback(event.data);
            });
            socket.addEventListener('close', function() {
                 setTimeout(function(){vpnServerSocketConnection(serverID, serverHostname, openCallback, messageCallback)}, 1000);
            });


        });
    };


    if ($.support.pageVisibility) {
        l('page visibiliyy');
    } else {
        l('no page visibiliyy');

    }

    vpnServerSocketConnection(123, 'hostname', function(socket) {
        l('socket open');
        socket.send('hello');
        socket.send(JSON.stringify({
            abc: 123
        }));
        socket.send(JSON.stringify({
            'subscribe': 'openconnect'
        }));
        socket.send(JSON.stringify({
            'subscribe': 'wireguard'
        }));
        socket.send(JSON.stringify({
            'subscribe': 'openvpn'
        }));
        socket.send(JSON.stringify({
            'startThread': 'openvpn'
        }));
    }, function(socketData) {
        l('socketData=', socketData);
    });

