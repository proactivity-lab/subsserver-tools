#!/usr/bin/env python

"""Simple data receiver for testing subsserver"""

__author__ = "Raido Pahtma"
__license__ = "MIT"

import json
import time
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.endpoints import UNIXServerEndpoint
from twisted.internet.protocol import Protocol, Factory
from twisted.web import server, resource


class WebserviceDataReceiver(resource.Resource):
    isLeaf = True

    def __init__(self, twisted_reactor, port):
        """
        @param twisted_reactor: Twisted reactor instance.
        @param port: Webservice port.
         @type port: int
        """
        resource.Resource.__init__(self)
        self.reactor = twisted_reactor
        self.name = None

        self.reactor.listenTCP(port, server.Site(self))

    #noinspection PyPep8Naming,PyUnusedLocal
    def render_GET(self, request):
        return '<html><body>...</body></html>'

    #noinspection PyPep8Naming
    def render_POST(self, request):
        request.setHeader("content-type", "application/json")
        if request.requestHeaders.hasHeader("content-type"):
            if "application/json" in request.requestHeaders.getRawHeaders("content-type"):
                try:
                    rj = json.loads(request.content.getvalue())
                    if self.name is not None:
                        print("%s %s:" % (self.name, time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())))
                    print(json.dumps(rj))
                    return json.dumps({"result": "SUCCESS"})
                except (ValueError, TypeError):
                    pass

        return json.dumps({"result": "FAIL"})


class SocketDataReceiver(Protocol):
    def __init__(self):
        pass

    #noinspection PyPep8Naming
    def dataReceived(self, data):
        if self.factory.name is not None:
            print("%s:" % (self.factory.name))
        print(data)
        self.transport.write(json.dumps({"result": "SUCCESS"}))
        self.transport.loseConnection()


class SocketDataReceiverFactory(Factory):
    protocol = SocketDataReceiver

    def __init__(self, endpoint):
        self.name = None
        self._endpoint = endpoint
        self._endpoint.listen(self)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Socket data receiver", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--webservice", default=9998, type=int, help="9998")
    parser.add_argument("--socket", default="/tmp/subsserver_data_receiver.sock", type=str, help="/tmp/subsserver_data_receiver.sock")
    parser.add_argument("--tcp", default=9997, type=int, help="9997")

    args = parser.parse_args()

    wdr = sdr = tdr = None
    if args.webservice is not None:
        wdr = WebserviceDataReceiver(reactor, args.webservice)
        wdr.name = "WEBSERVICE"

    if args.socket is not None:
        sdr = SocketDataReceiverFactory(UNIXServerEndpoint(reactor, args.socket))
        sdr.name = "SOCKET"

    if args.tcp is not None:
        tdr = SocketDataReceiverFactory(TCP4ServerEndpoint(reactor, args.tcp))
        tdr.name = "TCP"

    if wdr is None and sdr is None and tdr is None:
        print("What do you want me to do?")
        exit(1)

    reactor.run()

if __name__ == '__main__':
    main()
