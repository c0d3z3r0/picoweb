# Picoweb web pico-framework for Pycopy, https://github.com/pfalcon/pycopy
# Copyright (c) 2014-2020 Paul Sokolovsky
# SPDX-License-Identifier: MIT
import sys
import gc
import micropython
import utime
import uio
import ure as re
import uerrno
import uasyncio as asyncio
import pkg_resources

from .utils import parse_qs

SEND_BUFSZ = 128


def get_mime_type(fname):
    # Provide minimal detection of important file
    # types to keep browsers happy
    if fname.endswith(".html"):
        return "text/html", False
    if fname.endswith(".css"):
        return "text/css", True
    if fname.endswith(".js"):
        return "text/javascript", True
    if fname.endswith(".png") or fname.endswith(".jpg"):
        return "image", True
    return "text/plain", False

def sendstream(writer, f):
    buf = bytearray(SEND_BUFSZ)
    while True:
        l = f.readinto(buf)
        if not l:
            break
        yield from writer.awrite(buf, 0, l)

def jsonify(writer, dict):
    import ujson
    yield from start_response(writer, "application/json")
    yield from writer.awrite(ujson.dumps(dict))

def start_response(writer, content_type="text/html", status="200", headers=None,
                   charset="utf-8", cacheable=False, compressed=False):
    yield from writer.awrite("HTTP/1.0 %s NA\r\n" % status)
    if compressed:
        yield from writer.awrite('Content-Encoding: gzip\r\n')
    yield from writer.awrite("Content-Type: ")
    yield from writer.awrite(content_type)
    yield from writer.awrite("; charset=")
    yield from writer.awrite(charset)
    if not headers:
        yield from writer.awrite("\r\n\r\n")
        return
    yield from writer.awrite("\r\n")

    if isinstance(headers, bytes) or isinstance(headers, str):
        yield from writer.awrite(headers)
    else:
        for k, v in headers.items():
            if k == "Cache-Control":
                continue
            yield from writer.awrite(k)
            yield from writer.awrite(": ")
            yield from writer.awrite(v)
            yield from writer.awrite("\r\n")
    if cacheable:
        yield from writer.awrite("\r\nCache-Control: max-age=86400")
    yield from writer.awrite("\r\n")

def http_error(writer, status):
    yield from start_response(writer, status=status)
    yield from writer.awrite(str(status))


class HTTPRequest:

    def __init__(self):
        pass

    def read_data(self):
        size = int(self.headers["Content-Length"])
        self.data = yield from self.reader.readexactly(size)

    def read_form_data(self):
        self.form = parse_qs(self.data.decode())

    def parse_qs(self):
        self.form = parse_qs(self.qs)

    def read_json_data(self):
        import ujson
        yield from self.read_data()
        self.json = ujson.loads(self.data.decode())

class WebApp:

    def __init__(self, pkg, routes=None, serve_static=True):
        if routes:
            self.url_map = routes
        else:
            self.url_map = []
        if pkg and pkg != "__main__":
            self.pkg = pkg.split(".", 1)[0]
        else:
            self.pkg = None
        if serve_static:
            self.url_map.append((re.compile("^/(static/.+)"), self.handle_static))
        self.mounts = []
        self.inited = False
        # Instantiated lazily
        self.template_loader = None
        self.headers_mode = "parse"
        self.loop = asyncio.get_event_loop()

    def parse_headers(self, reader):
        headers = {}
        while True:
            line = yield from reader.readline()
            line = line.decode()

            if line == "\r\n":
                break
            k, v = line.split(":", 1)
            headers[k] = v.strip()
        return headers

    def _handle(self, reader, writer):
        if self.debug > 1:
            micropython.mem_info()

        close = True
        req = None
        try:
            request_line = yield from reader.readline()
            request_line = request_line.decode()
            if request_line == "":
                self.log.error("%s: EOF on request start" % reader)
                yield from writer.aclose()
                return
            req = HTTPRequest()
            method, path, proto = request_line.split()
            self.log.debug('%.3f %s %s "%s %s"' % (utime.time(), req, writer, method, path))
            path = path.split("?", 1)
            qs = ""
            if len(path) > 1:
                qs = path[1]
            path = path[0]

            #print("================")
            #print(req, writer)
            #print(req, (method, path, qs, proto), req.headers)

            # Find which mounted subapp (if any) should handle this request
            app = self
            while True:
                found = False
                for subapp in app.mounts:
                    root = subapp.url
                    #print(path, "vs", root)
                    if path[:len(root)] == root:
                        app = subapp
                        found = True
                        path = path[len(root):]
                        if not path.startswith("/"):
                            path = "/" + path
                        break
                if not found:
                    break

            # We initialize apps on demand, when they really get requests
            if not app.inited:
                app.init()

            # Find handler to serve this request in app's url_map
            found = False
            for e in app.url_map:
                pattern = e[0]
                handler = e[1]
                extra = {}
                if len(e) > 2:
                    extra = e[2]

                if path == pattern:
                    found = True
                    break
                elif not isinstance(pattern, str):
                    # Anything which is non-string assumed to be a ducktype
                    # pattern matcher, whose .match() method is called. (Note:
                    # Django uses .search() instead, but .match() is more
                    # efficient and we're not exactly compatible with Django
                    # URL matching anyway.)
                    m = pattern.match(path)
                    if m:
                        req.url_match = m
                        found = True
                        break

            if not found:
                headers_mode = "skip"
            else:
                headers_mode = extra.get("headers", self.headers_mode)

            if headers_mode == "skip":
                while True:
                    l = yield from reader.readline()
                    if l == b"\r\n":
                        break
            elif headers_mode == "parse":
                req.headers = yield from self.parse_headers(reader)
            else:
                assert headers_mode == "leave"

            if found:
                req.method = method
                req.path = path
                req.qs = qs
                req.reader = reader

                content_type = req.headers.get("Content-Type", "").split(',')[0]
                if content_type == "application/json":
                    yield from req.read_json_data()
                elif content_type == "application/x-www-form-urlencoded":
                    yield from req.read_form_data()

                close = yield from handler(req, writer)
            else:
                yield from start_response(writer, status="404")
                yield from writer.awrite("404\r\n")
            #print(req, "After response write")
        except Exception as e:
            self.log.exc(e, "%.3f %s %s %r" % (utime.time(), req, writer, e))
            yield from self.handle_exc(req, writer, e)

        if close is not False:
            yield from writer.aclose()
        self.log.debug("%.3f %s Finished processing request", utime.time(), req)

    def handle_exc(self, req, resp, e):
        # Can be overriden by subclasses. req may be not (fully) initialized.
        # resp may already have (partial) content written.
        # NOTE: It's your responsibility to not throw exceptions out of
        # handle_exc(). If exception is thrown, it will be propagated, and
        # your webapp will terminate.
        # This method is a coroutine.
        if 0: yield

    def mount(self, url, app):
        "Mount a sub-app at the url of current app."
        # Inspired by Bottle. It might seem that dispatching to
        # subapps would rather be handled by normal routes, but
        # arguably, that's less efficient. Taking into account
        # that paradigmatically there's difference between handing
        # an action and delegating responisibilities to another
        # app, Bottle's way was followed.
        app.url = url
        self.mounts.append(app)
        # TODO: Consider instead to do better subapp prefix matching
        # in _handle() above.
        self.mounts.sort(key=lambda app: len(app.url), reverse=True)

    def route(self, url, **kwargs):
        def _route(f):
            self.url_map.append((url, f, kwargs))
            return f
        return _route

    def add_url_rule(self, url, func, **kwargs):
        # Note: this method skips Flask's "endpoint" argument,
        # because it's alleged bloat.
        self.url_map.append((url, func, kwargs))

    def _load_template(self, tmpl_name):
        if self.template_loader is None:
            if self.debug:
                import utemplate.source
                self.template_loader = utemplate.source.Loader(self.pkg, "templates")
            else:
               import utemplate.compiled
               self.template_loader = utemplate.compiled.Loader(self.pkg, "templates")
        try:
            return self.template_loader.load(tmpl_name)
        except Exception as e:
            if self.debug:
                self.log.exc(e, "%.3f %r" % (utime.time(), e))
            elif (isinstance(e, OSError) and e.args[0] == uerrno.ENOENT) or \
                 (isinstance(e, ImportError)) and tmpl_name.replace('.', '_') in e.args[0]:
                self.log.warning("%.3f %r" % (utime.time(), e))
                import utemplate.source
                template_loader = utemplate.source.Loader(self.pkg, "templates")
                return template_loader.load(tmpl_name)
            else:
                self.log.exc(e, "%.3f %r" % (utime.time(), e))

    def render_template(self, writer, tmpl_name, args=()):
        tmpl = self._load_template(tmpl_name)
        for s in tmpl(*args):
            yield from writer.awritestr(s)

    def render_str(self, tmpl_name, args=()):
        #TODO: bloat
        tmpl = self._load_template(tmpl_name)
        return ''.join(tmpl(*args))

    def sendfile(self, writer, fname, content_type=None, headers=None, cacheable=False, compressable=False):
        if not content_type:
            content_type, cacheable = get_mime_type(fname)
        if self.debug:
            cacheable = False
        for compress in [True, False] if compressable else [False]:
            try:
                _fname = fname + (".gz" if compress else "")
                with pkg_resources.resource_stream(self.pkg, _fname) as f:
                    yield from start_response(writer, content_type, "200", headers,
                                cacheable=cacheable, compressed=compress)
                    yield from sendstream(writer, f)
                    return
            except OSError as e:
                if e.args[0] != uerrno.ENOENT:
                    raise
        yield from http_error(writer, "404")

    def handle_static(self, req, resp):
        path = req.url_match.group(1)
        self.log.debug("%.3f %s Static file request", utime.time(), path)
        if ".." in path:
            yield from http_error(resp, "403")
            return
        if "gzip" in req.headers.get("Accept-Encoding", "") and not self.debug:
            compressable = True
        else:
            compressable = False
        yield from self.sendfile(resp, path, compressable=compressable)

    def init(self):
        """Initialize a web application. This is for overriding by subclasses.
        This is good place to connect to/initialize a database, for example."""
        self.inited = True

    def run(self, host="127.0.0.1", port=8081, debug=False, lazy_init=False, log=None):
        if log is None:
            try:
                import ulogging
                log = ulogging.getLogger("picoweb")
                if debug > 0:
                    log.setLevel(ulogging.DEBUG)
            except:
                class DummyLogger:

                    def __init__(self, debug):
                        if debug >= 0:
                            self.__getattr__ = \
                                lambda x: print
                        else:
                            self.__getattr__ = \
                                lambda x: lambda y: None

                log = DummyLogger(debug)

        self.log = log
        self.debug = int(debug)

        gc.collect()
        self.init()
        if not lazy_init:
            for app in self.mounts:
                app.init()

        self.log.info("* Running on http://%s:%s/" % (host, port))
        self.loop.create_task(asyncio.start_server(self._handle, host, port))
        self.loop.run_forever()
        self.loop.close()
