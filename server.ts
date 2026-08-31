import express from 'express';
import http from 'http';
import path from 'path';
import { spawn } from 'child_process';
import { createServer as createViteServer } from 'vite';
import { createProxyMiddleware } from 'http-proxy-middleware';

async function startServer() {
  const app = express();
  const PORT = 3000;

  let pyProcess;
  try {
    pyProcess = spawn('python3', ['-m', 'uvicorn', 'backend.main:app', '--port', '8001', '--host', '0.0.0.0'], {
      stdio: 'inherit'
    });
    console.log('[Python Backend] Spawned FastAPI server on port 8001');
  } catch (err: any) {
    console.warn('[Python Backend] Could not spawn FastAPI process:', err.message);
  }

  const pythonProxy = createProxyMiddleware({
    target: 'http://127.0.0.1:8001',
    changeOrigin: true,
    ws: true,
    on: {
      error: (err, req: any, res: any) => {
        console.warn('[Proxy Warning] Python backend at 8001 unavailable.', err.message);
        if (res && res.writeHead && !res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Backend unavailable' }));
        }
      }
    }
  });

  // Use app.all with wildcards so express doesn't strip the base path
  app.all('/api/*', pythonProxy);
  app.all('/ws/*', pythonProxy);
  app.all('/docs', pythonProxy);
  app.all('/openapi.json', pythonProxy);

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const server = http.createServer(app);
  
  server.on('upgrade', (req, socket, head) => {
    if (req.url?.startsWith('/ws')) {
      (pythonProxy as any).upgrade?.(req, socket, head);
    }
  });

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
