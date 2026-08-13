# Phage: HTTP framing honor-matrix backend specs.
# License: Apache-2.0 License

"""One entry per backend UNDER TEST. Each spec starts a container that serves a trivial
200 on any request, bound to loopback on `port` via host networking (never a wide bind:
these are unauthenticated toy servers).

`parser` is the field that matters and the reason this table exists at all. The security
boundary is the parser, not the product: uvicorn ships two, and they disagree. Advisory
databases have a column for the product and no column for this.

Adding a backend is one entry. Keep the app trivial; the harness reads framing from the
number of HTTP responses the server emits, not from application logs, so no per-language
logging is needed.
"""

BACKENDS = [
    {
        "name": "Go net/http",
        "parser": "net/http",
        "image": "golang:1.23-alpine",
        "port": 9401,
        "app": r"""cat > /tmp/s.go <<'EOF'
package main
import ("net/http";"fmt")
func main(){
 http.HandleFunc("/",func(w http.ResponseWriter,r *http.Request){fmt.Fprint(w,"ok")})
 http.ListenAndServe("127.0.0.1:9401",nil)
}
EOF
go run /tmp/s.go""",
    },
    {
        "name": "Node 22",
        "parser": "llhttp",
        "image": "node:22-alpine",
        "port": 9402,
        "app": r"""cat > /tmp/s.js <<'EOF'
require('http').createServer((q,s)=>s.end('ok')).listen(9402,'127.0.0.1');
EOF
node /tmp/s.js""",
    },
    {
        "name": "uvicorn --http h11",
        "parser": "h11",
        "image": "python:3.12-slim",
        "port": 9403,
        "app": r"""pip install -q uvicorn h11 && cat > /tmp/a.py <<'EOF'
async def app(scope,receive,send):
    if scope["type"]!="http": return
    while True:
        m=await receive()
        if not m.get("more_body"): break
    await send({"type":"http.response.start","status":200,"headers":[(b"content-length",b"2")]})
    await send({"type":"http.response.body","body":b"ok"})
EOF
cd /tmp && uvicorn --http h11 --host 127.0.0.1 --port 9403 a:app""",
    },
    {
        "name": "uvicorn --http httptools",
        "parser": "httptools",
        "image": "python:3.12-slim",
        "port": 9404,
        "app": r"""pip install -q uvicorn httptools && cat > /tmp/a.py <<'EOF'
async def app(scope,receive,send):
    if scope["type"]!="http": return
    while True:
        m=await receive()
        if not m.get("more_body"): break
    await send({"type":"http.response.start","status":200,"headers":[(b"content-length",b"2")]})
    await send({"type":"http.response.body","body":b"ok"})
EOF
cd /tmp && uvicorn --http httptools --host 127.0.0.1 --port 9404 a:app""",
    },
    {
        "name": "Hypercorn",
        "parser": "h11",
        "image": "python:3.12-slim",
        "port": 9405,
        "app": r"""pip install -q hypercorn && cat > /tmp/a.py <<'EOF'
async def app(scope,receive,send):
    if scope["type"]!="http": return
    while True:
        m=await receive()
        if not m.get("more_body"): break
    await send({"type":"http.response.start","status":200,"headers":[(b"content-length",b"2")]})
    await send({"type":"http.response.body","body":b"ok"})
EOF
cd /tmp && hypercorn -b 127.0.0.1:9405 a:app""",
    },
    {
        "name": "gunicorn (sync)",
        "parser": "gunicorn http",
        "image": "python:3.12-slim",
        "port": 9406,
        "app": r"""pip install -q gunicorn && cat > /tmp/a.py <<'EOF'
def app(environ, start_response):
    try: environ["wsgi.input"].read()
    except Exception: pass
    start_response("200 OK",[("Content-Length","2")])
    return [b"ok"]
EOF
cd /tmp && gunicorn -b 127.0.0.1:9406 a:app""",
    },
    {
        "name": "Werkzeug (dev)",
        "parser": "werkzeug",
        "image": "python:3.12-slim",
        "port": 9407,
        "app": r"""pip install -q werkzeug && cat > /tmp/a.py <<'EOF'
from werkzeug.serving import run_simple
def app(environ, start_response):
    try: environ["wsgi.input"].read()
    except Exception: pass
    start_response("200 OK",[("Content-Length","2")])
    return [b"ok"]
run_simple("127.0.0.1",9407,app)
EOF
python /tmp/a.py""",
    },
    {
        "name": "Puma",
        "parser": "puma (C)",
        # nio4r builds a C extension; the alpine/musl image lacks the headers for it.
        "boot": 420,
        "image": "ruby:3.3",
        "port": 9408,
        "app": r"""gem install --no-document puma -q && cat > /tmp/c.ru <<'EOF'
run ->(env){ env["rack.input"].read rescue nil; [200,{"content-length"=>"2"},["ok"]] }
EOF
puma -b tcp://127.0.0.1:9408 /tmp/c.ru""",
    },
    {
        "name": "WEBrick",
        "parser": "webrick",
        "image": "ruby:3.3-alpine",
        "port": 9409,
        "app": r"""gem install --no-document webrick -q && cat > /tmp/s.rb <<'EOF'
require 'webrick'
s=WEBrick::HTTPServer.new(:BindAddress=>'127.0.0.1',:Port=>9409,:AccessLog=>[],:Logger=>WEBrick::Log.new(File::NULL))
s.mount_proc('/'){|q,r| r.body='ok'}
s.start
EOF
ruby /tmp/s.rb""",
    },
]
