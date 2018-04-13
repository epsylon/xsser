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
from threading import Thread
import socket
import time

class ReceiverThread(Thread):
    def __init__(self, client, addr, parent):
        Thread.__init__(self)
        self.daemon = True
        self.client = client
        self.parent = parent
    def run(self):
        data = self.client.recv(1024)
        if data:
            self.parent.data_arrived(data)
            self.client.send('thanks for coming!')
            self.client.close()
        self.parent.client_finished(self)

class HubThread(Thread):
    def __init__(self, parent):
        Thread.__init__(self)
        self.daemon = True
        self._clients = []
        self._armed = True
        self.ready = False
        self.running =False
        self.parent = parent
    def url_request(self, url):
        split_url = url.split("/")
        if len(split_url) > 2:
            if split_url[1] == 'success':
                self.parent.token_arrived(split_url[2])
    def data_arrived(self, data):
        data.split("\n")[0]
        if data.startswith("GET"):
            split_data = data.split()
            if len(split_data) > 1:
                self.url_request(split_data[1])
    def client_finished(self, _thread):
        self._clients.remove(_thread)
    def shutdown(self):
        if self.ready:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
        self.running = False
        self._armed = False
        self.ready = False
    def run(self):
        while not self.running and self._armed:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(('localhost', 19084))
                self.running = True
            except socket.error as e:
                #print("socket busy, retry opening")
                if e.errno == 98: # its in use wait a bit and retry
                    time.sleep(3)
        if not self._armed:
            return
        self.socket = s
        self.ready = True
        s.listen(1)
        while self.running and self._armed:
            try:
                conn, addr = s.accept()
            except socket.timeout:
                pass
            except socket.error, e:
                if self.ready == False:
                    return
                else:
                    break
            else:
                t = ReceiverThread(conn, addr, self)
                t.start()
                self._clients.append(t)
        if self.ready:
            s.close()
            self.ready = False
