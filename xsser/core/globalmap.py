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
import os
import gtk
import user
import gobject
from core.reporter import XSSerReporter
from core.curlcontrol import Curl
from glib import markup_escape_text
from collections import defaultdict
from threading import Thread
import traceback
import urllib
import urlparse
import math
import cairo
import gzip
import pangocairo
import time

class PointType(object):
    checked = 15
    success = 10
    failed = 5
    crawled = 0
    crashsite = -1

crash_color = [0.1,0.1,0.1]
checked_color = [0,0.8,0.8]
failed_color = [0.8,0.0,0.0]
success_color = [0.0,0.0,0.8]
crawl_color = [0.0,0.0,0.0]
def gtkcol(col):
    return [int(col[0]*65535),int(col[1]*65535),int(col[2]*65535)]

class MapPoint(object):
    def __init__(self, lat, lng, ptype, size, text): # 0, 5, 10, 15, 20 -> 20==checked
        self.latitude = lat
        self.longitude = lng
        self.size = size
        self.text = text
        self.reports = defaultdict(list)
        self.reports[ptype].append(text)
        self.type = ptype
        if ptype == PointType.crawled:
            self.color = crawl_color
        elif ptype == PointType.failed:
            self.color = failed_color
        elif ptype == PointType.success:
            self.color = success_color
        elif ptype == PointType.checked:
            self.color = checked_color
        else:
            self.color = crawl_color
        self.gtkcolor = gtkcol(self.color)

    def add_reports(self, report_type, reports):
        for report_type in set(reports.keys() + self.reports.keys()):
            self.reports[report_type].extend(reports[report_type])

class CrashSite(MapPoint):
    def __init__(self, lat, lng, size, desturl):
        MapPoint.__init__(self, lat, lng, PointType.crashsite, size, desturl)
 
class DownloadThread(Thread):
    def __init__(self, geomap, parent):
        Thread.__init__(self)
        self.daemon = True
        self._map = geomap
        self._parent = parent
    def run(self):
        geo_db_path = self._map.get_geodb_path()
        def reportfunc(current, blocksize, filesize):
            percent = min(float(current)/(filesize/float(blocksize)),1.0)
            self._parent.report_state('downloading map', percent)
        if not os.path.exists(os.path.dirname(geo_db_path)):
            os.makedirs(os.path.dirname(geo_db_path))
        self._parent.report_state('getting city database', 0.0)
        try:
            urllib.urlretrieve('http://xsser.03c8.net/map/GeoLiteCity.dat.gz',
                           geo_db_path+'.gz', reportfunc)
        except:
            try:
                urllib.urlretrieve('http://xsser.sf.net/map/GeoLiteCity.dat.gz',
                           geo_db_path+'.gz', reportfunc)
            except:
                try:
                    urllib.urlretrieve('http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz',
                           geo_db_path+'.gz', reportfunc)
                except:
                    self._parent.report_state('error downloading map', 0.0)
                    self._map.geomap_failed()
        else:
            self._parent.report_state('map downloaded (restart XSSer!!!!)', 0.0)
            f_in = gzip.open(geo_db_path+'.gz', 'rb')
            f_out = open(geo_db_path, 'wb')
            f_out.write(f_in.read())
            f_in.close()
            print('deleting gzipped file')
            os.remove(geo_db_path+'.gz')
            self._map.geomap_ready()

class GlobalMap(gtk.DrawingArea, XSSerReporter):
    def __init__(self, parent, pixbuf, onattack=False):
        gtk.DrawingArea.__init__(self)
        geo_db_path = self.get_geodb_path()
        self._parent = parent
        self._pixbuf = pixbuf
        self._cache_geo = {}
        self.geo = None
        self._onattack = onattack
        if not os.path.exists(geo_db_path):
            self._t = DownloadThread(self, parent)
            self._t.start()
        else:
            self.finish_init()

    def geomap_ready(self):
        gtk.gdk.threads_enter()
        gobject.timeout_add(0, self.finish_init)
        gtk.gdk.threads_leave()

    def geomap_failed(self):
        gtk.gdk.threads_enter()
        gobject.timeout_add(0, self.failed_init)
        gtk.gdk.threads_leave()

    def failed_init(self):
        if hasattr(self, '_t'):
            self._t.join()
            delattr(self, '_t')

    def finish_init(self):
        import GeoIP
        if hasattr(self, '_t'):
            self._t.join()
            delattr(self, '_t')
        parent = self._parent
        geo_db_path = self.get_geodb_path()
        Geo = GeoIP.open(geo_db_path, GeoIP.GEOIP_STANDARD)
        self.geo = Geo
        self.set_has_tooltip(True)
        self._max_points = 200
        self._lasttime = 0.0
        self.context = None
        self.mapcontext = None
        self._mappixbuf = None
        self._selected = []
        self._current_text = ["", 0.0]
        self._stats = [0,0,0,0,0,0,0]
        self.width = self._pixbuf.get_width()
        self.height = self._pixbuf.get_height()
        self._min_x = 0
        self._max_x = self.width
        self._drawn_points = []
        self._lines = []
        self._frozenlines = []
        self._points = []
        self._crosses = []
        self.connect("expose_event", self.expose)
        self.connect("query-tooltip", self.on_query_tooltip)
        if self.window:
            self.window.invalidate_rect(self.allocation, True)
        if not self._onattack:
            self.add_test_points()

    def get_geodb_path(self):
        ownpath = os.path.dirname(os.path.dirname(__file__))
        gtkpath = os.path.join(ownpath, 'gtk')
        if os.path.exists(os.path.join(gtkpath, 'GeoLiteCity.dat')):
            return os.path.join(gtkpath, 'GeoLiteCity.dat')
        else:
            return os.path.join(user.home, '.xsser', 'GeoLiteCity.dat')

    def find_points(self, x, y, distance=9.0):
        points = []
        self._selected = []
        for idx, point in enumerate(self._drawn_points):
            d_x = x-point[0]
            d_y = y-point[1]
            if d_y*d_y+d_x*d_x < distance:
                self._points[point[2]].size = 4.0
                points.append(self._points[point[2]])
                self._selected.append(point[2])
        if points:
            rect = gtk.gdk.Rectangle(0,0,self.width, self.height)
            self.window.invalidate_rect(rect, True)
        return points

    def on_query_tooltip(self, widget, x, y, keyboard_mode, tooltip):
        if not self.geo:
            return False
        points = self.find_points(x, y)
        if points:
            text = ""
            success = []
            finalsuccess = []
            failures = []
            crawls = []
            for point in points:
                finalsuccess.extend(point.reports[PointType.checked])
                success.extend(point.reports[PointType.success])
                failures.extend(point.reports[PointType.failed])
                crawls.extend(point.reports[PointType.crawled])
            if finalsuccess:
                text += "<b>browser checked sucesses:</b>\n"
                text += "\n".join(map(lambda s: markup_escape_text(s), finalsuccess))
                if failures or success:
                    text += "\n"

            if success:
                text += "<b>sucesses:</b>\n"
                text += "\n".join(map(lambda s: markup_escape_text(s), success))
                if failures:
                    text += "\n"
            if failures:
                text += "<b>failures:</b>\n"
                text += "\n".join(map(lambda s: markup_escape_text(s), failures))
            if crawls and not failures and not success:
                text += "<b>crawls:</b>\n"
                text += "\n".join(map(lambda s: markup_escape_text(s), crawls))

            tooltip.set_markup(str(text))
            return True
        return False

    def add_test_points(self):
        self.add_point(0.0, 0.0)
        self.add_point(0.0, 5.0)
        self.add_point(0.0, 10.0)
        self.add_point(0.0, 15.0)
        self.add_point(5.0, 0.0)
        self.add_point(10.0, 0.0)
        self.add_point(15.0, 0.0)

    def clear(self):
        self._points = []
        self._lines = []
        self.mapcontext = None
        self._frozenlines = []
        self._crosses = []
        self._stats = [0,0,0,0,0,0,0]

    def expose(self, widget, event):
        if not self.mapcontext:
            self._mappixbuf = self._pixbuf.copy()
            self.mapsurface = cairo.ImageSurface.create_for_data(self._mappixbuf.get_pixels_array(), 
                                               cairo.FORMAT_ARGB32,
                                               self.width,
                                               self.height,
                                               self._pixbuf.get_rowstride())
            self.mapcontext = cairo.Context(self.mapsurface)
        self.draw_frozen_lines()
        self.context = self.window.cairo_create()
      
        self.context.set_source_surface(self.mapsurface)
        self.context.rectangle(event.area.x, event.area.y,
                              event.area.width, event.area.height)
        self.context.clip()
        self.context.rectangle(event.area.x, event.area.y,
                              event.area.width, event.area.height)
        self.context.fill()
        self.context.set_source_color(gtk.gdk.Color(0,0,0))
        self._min_x = 5 # we have the scale at the left for now
        self._max_x = 0
        if self.geo:
            self.draw(self.context)
        return False

    def add_point(self, lng, lat, point_type=PointType.crawled, desturl="testpoint"):
        map_point = MapPoint(lat, lng, point_type, 5.0, desturl)
        map_point.x, map_point.y = self.plot_point(lat, lng)
        self._points.append(map_point)

    def add_cross(self, lng, lat, col=[0,0,0], desturl="testpoint"):
        for a in self._crosses:
            if a.latitude == lat and a.longitude == lng:
                return
        crash_site = CrashSite(lat, lng, 5.0, desturl)
        crash_site.x, crash_site.y = self.plot_point(lat, lng)
        self.adjust_bounds(crash_site.x, crash_site.y)
        self._crosses.append(crash_site)
        self.queue_redraw()

    def insert_point(self, lng, lat, col=[0,0,0], desturl="testpoint"):
        self._points.insert(0, MapPoint(lat, lng, point_type, 5.0, desturl))

    def _preprocess_points(self):
        newpoints = defaultdict(list)
        for point in self._points:
            key = (point.latitude, point.longitude)
            newpoints[key].append(point)

        self._points = []
        for points in newpoints.itervalues():
            win_type = points[0]
            win_size = points[0]
            for point in points[1:]:
                if point.type > win_type.type:
                    win_type = point
                if point.size > win_type.size:
                    win_size = point
            self._points.append(win_type)
            if win_type != win_size:
                self._points.append(win_size)
            for point in points:
                if not point in [win_size, win_type]:
                    win_type.add_reports(point.type, point.reports)
        if len(self._points) > self._max_points:
            self._points = self._points[:self._max_points]

    def draw_frozen_lines(self):
        for line in self._lines[len(self._frozenlines):]:
            if line[4] <= 0.5:
                self.draw_line(self.mapcontext, line)
                self._frozenlines.append(line)

    def draw(self, context, failures=True):
        self._preprocess_points()
        if self._lasttime == 0:
            self._lasttime = time.time()-0.04
        currtime = time.time()
        timepassed = currtime - self._lasttime
        redraw = False
        if failures:
            self._drawn_points = []
            for cross in reversed(self._crosses):
                if cross.size > 0.1:
                    cross.size -= timepassed*2
                else:
                    self._crosses.remove(cross)
                if cross.size > 0.1:
                    redraw = True
                self.draw_cross(cross)
            for line in reversed(self._lines[len(self._frozenlines):]):
                if line[4] > 0.5:
                    line[4] -= timepassed*2
                if line[4] > 0.5:
                    redraw = True
                self.draw_line(self.context, line)

        for idx, point in enumerate(self._points):
            if point.type >= PointType.success: 
                if failures:
                    continue
            else:
                if not failures:
                    continue
            if point.size > 1.0 and not idx in self._selected:
                point.size -= timepassed*2
                redraw = True
            elif point.size < 1.0:
                point.size = 1.0
            self.draw_point(point)
            x = point.x
            y = point.y
            self.adjust_bounds(x, y)
            self._drawn_points.append([x, y, idx])
        stat_f = 1.0
        if failures:
            mp = self._max_points
            self.draw_bar((-45,-160,crawl_color,(self._stats[0]%mp)*stat_f))
            self.draw_bar((-45,-155,failed_color,(self._stats[1]%mp)*stat_f))
            self.draw_bar((-45,-150,success_color,(self._stats[2]%mp)*stat_f))
            self.draw_bar((-45,-145,checked_color,(self._stats[3]%mp)*stat_f))
            if int(self._stats[0] / mp):
                self.draw_bar((-46,-160,crawl_color,-2-(self._stats[0]/mp)*stat_f))
            if int(self._stats[1] / mp):
                self.draw_bar((-46,-155,failed_color,-2-(self._stats[1]/mp)*stat_f))
            if int(self._stats[2] / mp):
                self.draw_bar((-46,-150,success_color,-2-(self._stats[2]/mp)*stat_f))
            if int(self._stats[3] / mp):
                self.draw_bar((-46,-145,checked_color,-2-(self._stats[3]/mp)*stat_f))
            self.draw(context, False)
        else:
            if self._current_text[1] > 0.0:
                self.draw_text(100, self.height-50, self._current_text[0])
                self._current_text[1] -= timepassed*4
            self._lasttime = currtime
        if redraw:
            self.queue_redraw()

    def adjust_bounds(self, x, y):
        if x-20 < self._min_x:
            self._min_x = x-20
        elif x+20 > self._max_x:
            self._max_x = x+20

    def draw_text(self, x, y, text):
        self.context.save()
        self.context.move_to(x, y)
        v = (5.0-self._current_text[1])/5.0
        self.context.scale(0.1+max(v, 1.0), 0.1+max(v, 1.0))
        self.context.set_source_color(gtk.gdk.Color(*gtkcol((v,)*3)))
        u = urlparse.urlparse(text)
        self.context.show_text(u.netloc)
        self.context.restore()

    def draw_bar(self, point):
        if point[3]:
            self.context.save()
            x, y = self.plot_point(point[0], point[1])
            self.context.set_source_rgb(*point[2])
            self.context.rectangle(x, y, 5, -(2.0+point[3]))
            self.context.fill()
            self.context.restore()
            return x, y

    def draw_line(self, context, line):
        if line[4]:
            context.save()
            x, y = self.plot_point(line[0], line[1])
            x2, y2 = self.plot_point(line[2], line[3])
            self.adjust_bounds(x, y)
            self.adjust_bounds(x2, y2)
            context.set_line_width(1.0)
            context.set_source_rgba(0.0, 0.0, 0.0, float(line[4])/5.0)
            context.move_to(x, y)
            context.rel_line_to(x2-x, y2-y)
            context.stroke()
            context.restore()

    def draw_point(self, point):
        if point.size:
            self.context.save()
            self.context.set_source_color(gtk.gdk.Color(*point.gtkcolor))
            self.context.translate(point.x, point.y)
            self.context.arc(0.0, 0.0, 2.4*point.size, 0, 2*math.pi)
            self.context.close_path()
            self.context.fill()
            self.context.restore()

    def draw_cross(self, point):
        if point.size:
            self.context.save()
            self.context.translate(point.x, point.y)
            self.context.rotate(point.size)
            self.context.set_line_width(0.8*point.size)
            self.context.set_source_color(gtk.gdk.Color(*point.gtkcolor))
            self.context.move_to(-3*point.size, -3*point.size)
            self.context.rel_line_to(6*point.size, 6*point.size)
            self.context.stroke()
            self.context.move_to(-3*point.size, +3*point.size)
            self.context.rel_line_to(6*point.size, -6*point.size)
            self.context.stroke()
            self.context.restore()


    def get_latlon_fromurl(self, url):
        parsed_url = urlparse.urlparse(url)
        split_netloc = parsed_url.netloc.split(":")
        if len(split_netloc) == 2:
            server_name, port = split_netloc
        else:
            server_name = parsed_url.netloc
            port = None

        if server_name in self._cache_geo:
            return self._cache_geo[server_name]
        Geodata = self.geo.record_by_name(server_name)
        if Geodata:
            country_name = Geodata['country_name']
            longitude = Geodata['longitude']
            latitude = Geodata['latitude']
            self._cache_geo[server_name] = (latitude, longitude)
            return latitude, longitude

    def start_attack(self):
        self.clear()

    def queue_redraw(self):
        rect = gtk.gdk.region_rectangle((self._min_x,0,self._max_x-self._min_x,
                                  self.height))
        if self.window:
            self.window.invalidate_region(rect, True)
            del rect

    def mosquito_crashed(self, dest_url, reason):
        self._current_text = [dest_url, 5.0]
        self._stats[4] += 1
        try:
            lat, lon = self.get_latlon_fromurl(dest_url)
        except:
            return
        self.add_cross(lon, lat, crash_color, dest_url)
        gtk.gdk.threads_enter()
        self.queue_redraw()
        gtk.gdk.threads_leave()

    def add_checked(self, dest_url):
        self._current_text = [dest_url, 5.0]
        self._stats[3] += 1
        try:
            lat, lon = self.get_latlon_fromurl(dest_url)
        except:
            return
        self.add_point(lon, lat, PointType.checked, dest_url)
        gtk.gdk.threads_enter()
        self.queue_redraw()
        gtk.gdk.threads_leave()

    def add_success(self, dest_url):
        self._current_text = [dest_url, 5.0]
        self._stats[2] += 1
        try:
            lat, lon = self.get_latlon_fromurl(dest_url)
        except:
            return
        self.add_point(lon, lat, PointType.success, dest_url)
        gtk.gdk.threads_enter()
        self.queue_redraw()
        gtk.gdk.threads_leave()

    def add_failure(self, dest_url):
        self._current_text = [dest_url, 5.0]
        self._stats[1] += 1
        try:
            lat, lon = self.get_latlon_fromurl(dest_url)
        except:
            return
        self.add_point(lon, lat, PointType.failed, dest_url)
        gtk.gdk.threads_enter()
        self.queue_redraw()
        gtk.gdk.threads_leave()

    def add_link(self, orig_url, dest_url):
        try:
            lat, lon = self.get_latlon_fromurl(orig_url)
        except:
            return
        try:
            d_lat, d_lon = self.get_latlon_fromurl(dest_url)
        except:
            return
        if lat == d_lat and lon == d_lon:
            return
        for a in self._lines:
            if a[0] == lat and a[1] == lon and a[2] == d_lat and a[3] == d_lon:
                return
        self._lines.append([lat, lon, d_lat, d_lon, 0.5])

    def start_crawl(self, dest_url):
        self._current_text = [dest_url, 5.0]
        self._stats[0] += 1
        try:
            lat, lon = self.get_latlon_fromurl(dest_url)
        except:
            return
        self.add_point(lon, lat, PointType.crawled, dest_url)
        gtk.gdk.threads_enter()
        self.queue_redraw()
        gtk.gdk.threads_leave()

    def plot_point_mercator(self, lat, lng):
        longitude_shift = -23
        map_width = self.width
        map_height = self.height
        y_pos =  -1

        x = int((map_width * (180.0 + lng) / 360.0) + longitude_shift) % map_width
        lat = lat * math.pi / 180;  # convert from degrees to radians
        y = math.log(math.tan((lat/2.0) + (math.pi/4.0)))
        y = (map_height / 2.0) - (map_width * y / (2.0*math.pi)) + y_pos
        return x, y

    def plot_point_mercatormiller(self, lat, lng):
        longitude_shift = 0
        map_width = self.width
        map_height = self.height
        y_pos = 70

        x = int((map_width * (180.0 + lng) / 360.0) + longitude_shift) % map_width
        lat = lat * math.pi / 180.0;  # convert from degrees to radians
        y = 1.25*math.log(math.tan((lat/2.5) + (math.pi/4.0)))
        y = (map_height / 2.0) - (map_width * y / (2.0*math.pi)) + y_pos
        return x, y

    def plot_point_equirectangular(self, lat, lng):
        longitude_shift = -23
        map_width = self.width
        map_height = self.height
        y_pos = 0
        magic_factor = 1.1
        x = int((map_width * (180.0 + lng) / 360.0) + longitude_shift) % map_width
        y = int((map_height / 2.0) - int((map_height * (lat) / 180.0)*magic_factor))
        return x,y

    def plot_point(self, lat, lng):
        x, y = self.plot_point_equirectangular(lat, lng)

        if x-20 < self._min_x:
            self._min_x = x-20
        if x+20 > self._max_x:
            self._max_x = x+20
        return x, y
