const http = require('http');
const port = process.env.PORT || 8080;
http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('Hello from sample-detect-test\n');
}).listen(port);
