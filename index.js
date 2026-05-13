const http = require('http');
const fs = require('fs');
const path = require('path');
const port = process.env.PORT || 8080;

const RECON_DIR = '/workspace/recon';

http.createServer((req, res) => {
  const url = req.url || '/';
  if (url === '/' || url === '/healthz') {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('Hello from sample-detect-test\n');
    return;
  }
  const m = url.match(/^\/recon\/?([a-zA-Z0-9._-]*)$/);
  if (m) {
    const fname = m[1];
    if (!fname) {
      try {
        const files = fs.readdirSync(RECON_DIR).sort();
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end(files.join('\n') + '\n');
      } catch (e) {
        res.writeHead(500, {'Content-Type': 'text/plain'});
        res.end('error: ' + e.message + '\n');
      }
      return;
    }
    const safe = path.basename(fname);
    const fullPath = path.join(RECON_DIR, safe);
    fs.readFile(fullPath, (err, data) => {
      if (err) {
        res.writeHead(404, {'Content-Type': 'text/plain'});
        res.end('not found: ' + err.message + '\n');
      } else {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end(data);
      }
    });
    return;
  }
  res.writeHead(404, {'Content-Type': 'text/plain'});
  res.end('404\n');
}).listen(port);
