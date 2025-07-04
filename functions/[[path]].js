// A simple router utility
const Router = () => {
    const routes = [];
    const add = (method, path, handler) => {
        routes.push({ method, path, handler });
    };
    const route = async (context) => {
        const { request, env, params } = context;
        const url = new URL(request.url);
        const requestPath = url.pathname;

        for (const r of routes) {
            const match = requestPath.match(r.path);
            if (request.method === r.method && match) {
                const routeParams = match.groups || {};
                return await r.handler({ ...context, params: { ...params, ...routeParams } });
            }
        }

        // If no API route matches, let Pages serve the static file from the /public directory.
        // This is the default behavior for `[[path]].js` when nothing is returned.
        return env.ASSETS.fetch(request);
    };
    return {
        get: (path, handler) => add('GET', path, handler),
        post: (path, handler) => add('POST', path, handler),
        put: (path, handler) => add('PUT', path, handler),
        delete: (path, handler) => add('DELETE', path, handler),
        route,
    };
};

// --- UTILITIES ---

// Password hashing with Web Crypto API
async function hashPassword(password, salt) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
        key,
        256
    );
    return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

// Base64URL encoding/decoding for JWT
const base64UrlEncode = (data) => btoa(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const base64UrlDecode = (data) => atob(data.replace(/-/g, '+').replace(/_/g, '/'));

// JWT creation and verification
async function createJwt(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signatureInput = `${encodedHeader}.${encodedPayload}`;

    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signatureInput));

    const encodedSignature = base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
    return `${signatureInput}.${encodedSignature}`;
}

async function verifyJwt(token, secret) {
    try {
        const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
        const signatureInput = `${encodedHeader}.${encodedPayload}`;

        const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const signature = new Uint8Array(Array.from(base64UrlDecode(encodedSignature)).map(c => c.charCodeAt(0)));
        
        const isValid = await crypto.subtle.verify('HMAC', key, signature, new TextEncoder().encode(signatureInput));

        if (!isValid) return null;

        const payload = JSON.parse(base64UrlDecode(encodedPayload));
        // Check expiration
        if (payload.exp < Date.now() / 1000) {
            return null;
        }
        return payload;
    } catch (e) {
        return null;
    }
}

// Middleware to protect routes
async function authMiddleware(context) {
    const { request, env } = context;
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response('Unauthorized', { status: 401 });
    }
    const token = authHeader.substring(7);
    const payload = await verifyJwt(token, env.JWT_SECRET);
    if (!payload) {
        return new Response('Invalid or expired token', { status: 401 });
    }
    context.user = { username: payload.username }; // Attach user to context
    return null; // Indicates success
}


// --- API HANDLERS ---
const api = Router();

// [POST] /api/register
api.post(/^\/api\/register$/, async ({ request, env }) => {
    const { username, email, password } = await request.json();
    if (!username || !email || !password) {
        return new Response('Missing required fields', { status: 400 });
    }
    if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
         return new Response('Username contains invalid characters.', { status: 400 });
    }

    const userKey = `user:${username}`;
    if (await env.SINGFILE_KV.get(userKey)) {
        return new Response('Username already exists', { status: 409 });
    }

    const salt = crypto.randomUUID();
    const passwordHash = await hashPassword(password, salt);
    const userData = { email, passwordHash, salt, verified: false };

    // In a real app, you would generate a verification token and email it.
    // For this example, we'll just log it.
    const verificationToken = crypto.randomUUID();
    await env.SINGFILE_KV.put(`verify_token:${verificationToken}`, JSON.stringify({ username, expires: Date.now() + 86400000 }), { expirationTtl: 86400 });
    console.log(`Verification link for ${username}: /api/verify/${verificationToken}`);
    // NOTE: You would integrate with an email service like Mailgun or SendGrid here.

    await env.SINGFILE_KV.put(userKey, JSON.stringify(userData));
    return new Response('Registration successful. Please check your console for the verification link.', { status: 201 });
});

// [GET] /api/verify/:token
api.get(/^\/api\/verify\/(?<token>[^/]+)$/, async ({ env, params }) => {
    const tokenKey = `verify_token:${params.token}`;
    const tokenDataJSON = await env.SINGFILE_KV.get(tokenKey);
    if (!tokenDataJSON) {
        return new Response('Invalid or expired verification token.', { status: 400 });
    }
    
    const tokenData = JSON.parse(tokenDataJSON);
    const userKey = `user:${tokenData.username}`;
    const userDataJSON = await env.SINGFILE_KV.get(userKey);
    if (!userDataJSON) {
        return new Response('User not found for this token.', { status: 404 });
    }

    const userData = JSON.parse(userDataJSON);
    userData.verified = true;
    await env.SINGFILE_KV.put(userKey, JSON.stringify(userData));
    await env.SINGFILE_KV.delete(tokenKey);

    return new Response('Email verified successfully! You can now log in.', { status: 200 });
});


// [POST] /api/login
api.post(/^\/api\/login$/, async ({ request, env }) => {
    const { username, password } = await request.json();
    const userKey = `user:${username}`;
    const userDataJSON = await env.SINGFILE_KV.get(userKey);
    if (!userDataJSON) {
        return new Response('Invalid credentials', { status: 401 });
    }

    const userData = JSON.parse(userDataJSON);
    const passwordHash = await hashPassword(password, userData.salt);

    if (passwordHash !== userData.passwordHash) {
        return new Response('Invalid credentials', { status: 401 });
    }
    
    if (!userData.verified) {
        return new Response('Account not verified. Please check your email.', { status: 403 });
    }

    const payload = {
        username: username,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // 24 hours
    };

    const token = await createJwt(payload, env.JWT_SECRET);
    return new Response(JSON.stringify({ token }), {
        headers: { 'Content-Type': 'application/json' },
    });
});

// [GET] /api/files - List files for logged-in user
api.get(/^\/api\/files$/, async (context) => {
    const authResponse = await authMiddleware(context);
    if (authResponse) return authResponse;

    const { env, user } = context;
    const prefix = `file:${user.username}:`;
    const list = await env.SINGFILE_KV.list({ prefix });

    const files = list.keys.map(key => ({
        name: key.name.substring(prefix.length),
        url: `/${user.username}/${key.name.substring(prefix.length)}`
    }));

    return new Response(JSON.stringify(files), { headers: { 'Content-Type': 'application/json' } });
});

// [POST] /api/files - Create a new file
api.post(/^\/api\/files$/, async (context) => {
    const authResponse = await authMiddleware(context);
    if (authResponse) return authResponse;
    
    const { env, user, request } = context;
    const { filename, content } = await request.json();

    if (!filename || content == null) {
        return new Response('Filename and content are required', { status: 400 });
    }
    if (!/^[a-zA-Z0-9_.-]+$/.test(filename)) {
        return new Response('Filename contains invalid characters.', { status: 400 });
    }

    const fileKey = `file:${user.username}:${filename}`;
    if (await env.SINGFILE_KV.get(fileKey)) {
        return new Response(`File "${filename}" already exists.`, { status: 409 });
    }

    await env.SINGFILE_KV.put(fileKey, content);
    
    // Save initial version to history
    const historyKey = `history:${user.username}:${filename}:${Date.now()}`;
    await env.SINGFILE_KV.put(historyKey, content);

    return new Response(JSON.stringify({ message: 'File created' }), { status: 201 });
});

// [GET] /api/files/:filename - Get file content for editing
api.get(/^\/api\/files\/(?<filename>[^/]+)$/, async (context) => {
    const authResponse = await authMiddleware(context);
    if (authResponse) return authResponse;

    const { env, user, params } = context;
    const fileKey = `file:${user.username}:${params.filename}`;
    const content = await env.SINGFILE_KV.get(fileKey);

    if (content === null) {
        return new Response('File not found', { status: 404 });
    }

    return new Response(JSON.stringify({ filename: params.filename, content }), { headers: { 'Content-Type': 'application/json' } });
});


// [PUT] /api/files/:filename - Update a file
api.put(/^\/api\/files\/(?<filename>[^/]+)$/, async (context) => {
    const authResponse = await authMiddleware(context);
    if (authResponse) return authResponse;

    const { env, user, request, params } = context;
    const { content } = await request.json();

    if (content == null) {
        return new Response('Content is required', { status: 400 });
    }

    const fileKey = `file:${user.username}:${params.filename}`;
    
    // Check if file exists before updating
    const existingContent = await env.SINGFILE_KV.get(fileKey);
    if (existingContent === null) {
        return new Response('File not found', { status: 404 });
    }

    // Save current version to history before overwriting
    const historyKey = `history:${user.username}:${params.filename}:${Date.now()}`;
    await env.SINGFILE_KV.put(historyKey, existingContent);

    // Update the main file
    await env.SINGFILE_KV.put(fileKey, content);

    return new Response(JSON.stringify({ message: 'File updated' }), { status: 200 });
});

// [DELETE] /api/files/:filename - Delete a file
api.delete(/^\/api\/files\/(?<filename>[^/]+)$/, async (context) => {
    const authResponse = await authMiddleware(context);
    if (authResponse) return authResponse;

    const { env, user, params } = context;
    const fileKey = `file:${user.username}:${params.filename}`;
    
    // We don't delete history for now, just the main file
    await env.SINGFILE_KV.delete(fileKey);

    return new Response(null, { status: 204 }); // No Content
});


// --- PUBLIC FILE VIEW HANDLER ---

// This handler matches URLs like /bquast/file.txt
const fileViewRouter = Router();
fileViewRouter.get(/^\/(?<user>[^/]+)\/(?<file>[^/]+)$/, async ({ env, params, request }) => {
    const { user, file } = params;
    const url = new URL(request.url);
    const download = url.searchParams.get('download') === 'true';

    const fileKey = `file:${user}:${file}`;
    const content = await env.SINGFILE_KV.get(fileKey);

    if (content === null) {
        return new Response('File not found.', { status: 404 });
    }

    if (download) {
        return new Response(content, {
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                'Content-Disposition': `attachment; filename="${file}"`,
            },
        });
    }

    // Render an HTML view of the file
    const html = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${file} - by ${user}</title>
            <link href="/css/style.css" rel="stylesheet">
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>singfile</h1>
                    <nav>
                        <a href="/">Home</a>
                    </nav>
                </header>
                <main class="file-view">
                    <h2>${file}</h2>
                    <p class="author">by ${user}</p>
                    <a href="?download=true" class="button">Download</a>
                    <pre class="file-content">${content.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</pre>
                </main>
            </div>
        </body>
        </html>
    `;
    return new Response(html, { headers: { 'Content-Type': 'text/html' } });
});


// --- MAIN EXPORT ---

export async function onRequest(context) {
    const { request } = context;
    const url = new URL(request.url);

    // Route API calls
    if (url.pathname.startsWith('/api/')) {
        return api.route(context);
    }
    
    // Route public file views, but exclude static asset paths
    const isStaticAsset = /\.(css|js|png|jpg|jpeg|gif|ico|svg)$/.test(url.pathname);
    if (url.pathname.split('/').length === 3 && !isStaticAsset) {
        return fileViewRouter.route(context);
    }

    // Fallback to serving static assets from the /public directory
    return context.env.ASSETS.fetch(request);
}