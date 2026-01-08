import type { IncomingMessage, ServerResponse } from 'http';

const BACKEND_URL = 'http://127.0.0.1:8000';

export async function handleProxy(req: IncomingMessage, res: ServerResponse) {
  const url = req.url || '';
  
  // Only proxy API requests
  if (!url.startsWith('/api') && !url.startsWith('/health')) {
    return false;
  }
  
  const targetUrl = `${BACKEND_URL}${url}`;
  
  try {
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: {
        ...req.headers as Record<string, string>,
        host: '127.0.0.1:8000',
      },
      body: req.method !== 'GET' && req.method !== 'HEAD' ? await getBody(req) : undefined,
    });
    
    // Copy response headers
    response.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });
    
    // Copy status
    res.statusCode = response.status;
    
    // Stream response body
    const body = await response.text();
    res.end(body);
    
    return true;
  } catch (error) {
    console.error('Proxy error:', error);
    res.statusCode = 502;
    res.end('Bad Gateway');
    return true;
  }
}

async function getBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => resolve(body));
  });
}
