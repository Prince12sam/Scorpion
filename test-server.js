import http from 'http';

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  if (req.url === '/api/health') {
    res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
  } else {
    res.end(JSON.stringify({ message: 'Scorpion Test Server Running' }));
  }
});

const PORT = 3003;
server.listen(PORT, () => {
  console.log(`🧪 Test Server running on http://localhost:${PORT}`);
  console.log('Testing basic connectivity...');
});

export default server;