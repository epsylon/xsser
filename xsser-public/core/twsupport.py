#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
$Id$

This file is part of the xsser project, http://xsser.03c8.net

Copyright (c) 2011/2016 psy <epsylon@riseup.net>

xsser is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 3 of the License.

xsser is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with xsser; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import sys
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.internet import reactor
from core.main import xsser
import cgi
import traceback
try:
    from orbited.start import main as orbited_main
except:
    print "no orbited so not enabling rt swarm port"
    orbited_main = None
    traceback.print_exc()

print "\nXSSer v1.7b: The Mosquito 'Zika Swarm'\n"
print "Daemon(s): ready!", "//" , "Interfaz: ready!\n"
print "Connect to http://127.0.0.1:19084/static/ via Web or Telnet to manage your swarm\n"
print "Listening..."

from twisted.web import resource, error, script, server
from orbited import __version__ as version

class XSSerResource(resource.Resource):
    def __init__(self, name, parent):
        self.name = str(name)
        self.parent = parent
    def render_GET(self, request):
        if hasattr(self.parent, "do_"+self.name):
            response = getattr(self.parent, "do_"+self.name)(request)
        else:
            response = "<h2>The swarm is not ready to "+self.name+"</h2>"
        return response
    def render_POST(self, request):
        return self.render_GET(request)

class XSSerCheckerResource(resource.Resource):
    def __init__(self, name, parent):
        self.name = str(name)
        self.parent = parent
    def render_GET(self, request):
        print "SUCCESS!!", request
        self.parent.xsser.final_attack_callback(request)
        response = "thx for use XSSer (http://xsser.03c8.net) !!"
        return response
    def render_POST(self, request):
        return self.render_GET(request)

class XSSerMainResource(script.ResourceScriptDirectory):
    def __init__(self, name, xsser):
        script.ResourceScriptDirectory.__init__(self, name)
        self.xsser = xsser
    def render(self, request):
        response = "<h2>XSSer.system</h2>"
        response += " version: "+version
        app = self.xsser()
        options = app.create_options(["-d","http://Bla.com"])
        app.set_options(options)
        response += "<br><br>&gt; <a href='/static'>Static</a>"
        response += "<br>&gt; <a href='/system/monitor'>Orbited.system.monitor</a><br><br>"
        response += "<h2>Options</h2>"
        for opt in app.options.__dict__:
            if not hasattr(app.options.__dict__[opt], "__call__"):
                response += "<b>"+str(opt) + "</b> " + str(app.options.__dict__[opt]) + "<br/>"
        return response
    def do_attack(self, request):
        response = "<h2>Let's go attack</h2>"
        return response
    def do_success(self, request):
        response = "not implemented!"
        if False:
            print "SUCCESS!!", data.split('HTTP')[0].split('/')[-1]
            self.factory.xsser.final_attack_callback(data.split('HTTP')[0].split('/')[-1].strip())
            self.sendHTTP("thx for use XSSer (http://xsser.03c8.net) !!\n")
        return response
    def do_evangelion(self, request):
        response = "Start Swarm Attack"
        reactor.callInThread(self.xsser.run)
        return response
    def getChild(self, path, request):
        return XSSerResource(path, self)

class XSSerProtocol(Protocol):
    transport = None
    factory = None
    def connectionMade(self):
        self.factory._clients.append(self)
        print "new client connected..."
    def connectionLost(self, reason):
        self.factory._clients.remove(self)
    def sendHTTP(self, data):
        self.transport.write("HTTP/1.0 200 Found\n")
        self.transport.write("Content-Type: text/html; charset=UTF-8\n\n")
        self.transport.write(data)
    def dataReceived(self, data):
        print "Mosquito network ready ;)",data
        if (data.startswith("GET") and "evangelion" in data) or "evangelion" in data:
            print "EVAngelion swarm mode!\n"
            self.sendHTTP("Start Swarm Attack\n")
            app = xsser()
            app.set_reporter(self.factory)
            self.factory.xsser = app
            data = data.split('\n')[0]
            options = data.replace('GET ', '').split()[1:]
            print 'OPTIONS',options
            if len(options) > 1:
                reactor.callInThread(self.factory.xsser.run, options)
            else:
                reactor.callInThread(self.factory.xsser.run)
        elif "evangelion" in data:
            self.sendHTTP("Start Swarm Attack\n")
            reactor.callInThread(self.factory.xsser.run)
        elif data.startswith("GET /success"):
            print "SUCCESS!!", data.split('HTTP')[0].split('/')[-1]
            self.factory.xsser.final_attack_callback(data.split('HTTP')[0].split('/')[-1].strip())
            self.sendHTTP("thx for use XSSer (http://xsser.03c8.net) !!\n")
            self.transport.loseConnection()
        elif data.startswith("GET"):
            self.sendHTTP("XSSer Web Interface <a href='evangelion'>Try it!</a>\n")
        elif data.startswith("close"):
            reactor.stop()
        else:
            self.transport.write("1")

class ServerFactory(Factory):
    protocol = XSSerProtocol
    _clients = []
    def __init__(self, xsser):
        self.xsser = xsser
    def post(self, data):
        for c in self._clients:
            c.transport.write(cgi.escape(data)+'<br/>')

if __name__ == '__main__':
    if orbited_main:
        print "orbited!"
        root = orbited_main()
        import orbited.transports.base
        from orbited import cometsession
        tcpresource = resource.Resource()
        reactor.listenWith(cometsession.Port, factory=ServerFactory(xsser),
                           resource=root, childName='xssertcp')
        root.putChild("xsser", XSSerMainResource("xsser", xsser))
        root.putChild("checker", XSSerCheckerResource("checker", xsser))                        
    else:
        factory = ServerFactory(None)
        reactor.listenTCP(19084, factory)
    reactor.run()
