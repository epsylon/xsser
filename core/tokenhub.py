#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
This file is part of the XSSer project, https://xsser.03c8.net

Copyright (c) 2010/2020 | psy <epsylon@riseup.net>

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

success_token_url = False
token_arrived_hash = None

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
            self.client.send(b'XSSer "token-hub" service running... ;-)\n\n')
            self.client.send(b'### INCOMING DATA:\n\n')
            self.client.send(data)
            self.client.close()
        self.parent.client_finished(self)

class HubThread(Thread):
    def __init__(self, parent):
        Thread.__init__(self)
        self.daemon = True
        self._clients = []
        self._armed = True
        self.ready = False
        self.running = False
        self.parent = parent
        self.token_arrived_flag = False
        self.success_arrived_flag = False
    def check_hash(self, hashing):
        if token_arrived_hash:
            if success_token_url:
                if token_arrived_hash == hashing: # [100% VULNERABLE] check!
                    self.token_arrived_flag = True
                    self.success_arrived_flag = False
                elif '/success/' in success_token_url:
                    self.token_arrived_flag = True
                    self.success_arrived_flag = True
                else:
                    self.token_arrived_flag = False
            else:
                self.token_arrived_flag = False
        else:
            self.token_arrived_flag = False
        return self.token_arrived_flag, self.success_arrived_flag, token_arrived_hash
    def url_request(self, url):
        split_url = url.split(b"/")
        if len(split_url) > 2:
            if split_url[1] == b'success':
                global success_token_url
                global token_arrived_hash
                success_token_url = url.decode('utf-8')
                token_arrived_hash = split_url[2].decode('utf-8')
                self.parent.token_arrived(split_url[2].decode('utf-8'))
    def data_arrived(self, data):
        data.split(b"\n")[0]
        if data.startswith(b"GET"):
            split_data = data.split()
            if len(split_data) > 1:
                self.url_request(split_data[1])
    def client_finished(self, _thread):
        try:
            self._clients.remove(_thread)
        except:
            pass
    def shutdown(self):
        if self.ready:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except OSError:
                pass
        self.running = False
        self._armed = False
        self.ready = False
    def run(self):
        while not self.running and self._armed:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # try re-use socket
                s.bind(('localhost', 19084))
                self.running = True
            except socket.error as e:
                #print("socket busy, retry opening:", e)
                if e.errno == 98: # its in use wait a bit and retry
                    time.sleep(5)
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
            except socket.error as e:
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
