// Chunked-aware ground-truth backend (Node/llhttp). Unlike the CL-only conn_bk, this
// parses transfer-encoding: chunked correctly, so it can tell a faithful re-frame from a
// real desync: one forwarded byte-stream that llhttp splits into >1 request = a smuggle.
// Logs per request: method, url, CL, TE, body length, trailers, and per-connection index.
const http = require("http");
const fs = require("fs");
const LOG = process.env.CHUNK_LOG || "/logs/chunk_bk.log";
function log(s) { fs.appendFileSync(LOG, s + "\n"); }

let connId = 0;
const server = http.createServer((req, res) => {
  const cid = req.socket._cid;
  let bodyLen = 0;
  req.on("data", (c) => { bodyLen += c.length; });
  req.on("end", () => {
    const te = req.headers["transfer-encoding"] || "";
    const cl = req.headers["content-length"] || "";
    const tr = JSON.stringify(req.trailers || {});
    log(`REQ conn=${cid} ${req.method} ${req.url} cl=${cl} te=${te} body=${bodyLen} trailers=${tr}`);
    // respond-then-keep-alive so a pooled desynced conn stays observable
    res.writeHead(200, { "Content-Length": "3", "Connection": "keep-alive" });
    res.end("ok\n");
  });
});
server.on("connection", (s) => { s._cid = ++connId; log(`CONN ${connId}`); });
server.on("clientError", (err, sock) => {
  log(`CLIENTERROR ${err.code || err.message}`);
  try { sock.destroy(); } catch (e) {}
});
server.listen(8080, "0.0.0.0", () => log("LISTEN 8080"));
