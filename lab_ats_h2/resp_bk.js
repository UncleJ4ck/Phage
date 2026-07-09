// Response-side probe backend: every request gets a CHUNKED response carrying an HTTP
// trailer (X-Injected: SMUGGLED_RESP). Tests how ATS converts an H1 response trailer to the
// H2 client: dropped, forwarded as an H2 trailer, or mangled (the response-side of the
// request-trailer 'HTTP/1.0 0 ' type confusion, which on the response path could mean
// response splitting / header injection). Also emits a marker header for baseline.
const http = require("http");
const server = http.createServer((req, res) => {
  req.on("data", () => {});
  req.on("end", () => {
    res.writeHead(200, {
      "Content-Type": "text/plain",
      "Trailer": "X-Injected",
      "X-Marker": "baseline",
      "Transfer-Encoding": "chunked",
    });
    res.write("BODY5");
    res.addTrailers({ "X-Injected": "SMUGGLED_RESP" });
    res.end();
  });
});
server.listen(8080, "0.0.0.0", () => console.log("resp_bk LISTEN 8080"));
