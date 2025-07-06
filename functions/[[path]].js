import git from 'isomorphic-git';
import { Volume } from 'memfs';
import { zipSync } from 'fflate';

const Router = () => {
    const routes = [];
    const add = (method, path, handler) => { routes.push({ method, path, handler }); };
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
        return env.ASSETS.fetch(request);
    };
    return { get: (p, h) => add('GET', p, h), post: (p, h) => add('POST', p, h), put: (p, h) => add('PUT', p, h), delete: (p, h) => add('DELETE', p, h), route, };
};

async function hashPassword(password, salt) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
    return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

const base64UrlEncode = (data) => btoa(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const base64UrlDecode = (data) => atob(data.replace(/-/g, '+').replace(/_/g, '/'));

async function createJwt(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signatureInput));
    return `${signatureInput}.${base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)))}`;
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
        if (payload.exp < Date.now() / 1000) return null;
        return payload;
    } catch (e) { return null; }
}

async function authMiddleware(context) {
    const authHeader = context.request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return new Response('Unauthorized', { status: 401 });
    const token = authHeader.substring(7);
    const payload = await verifyJwt(token, context.env.JWT_SECRET);
    if (!payload) return new Response('Invalid or expired token', { status: 401 });
    context.user = { username: payload.username };
    return null;
}

async function sendVerificationEmail({ env, request }, to, username, token) {
    const verificationLink = `${new URL(request.url).origin}/api/verify/${token}`;
    const emailBody = {
        from: 'Singfile Verification <verify@yourdomain.com>', // MAKE SURE THIS IS YOUR VERIFIED RESEND DOMAIN
        to: [to],
        subject: 'Verify your email for Singfile',
        html: `<h1>Welcome, ${username}!</h1><p>Click the link to verify your email:</p><a href="${verificationLink}">Verify Email</a>`,
    };
    const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(emailBody),
    });
    if (!response.ok) console.error('Failed to send email:', await response.text());
}

const api = Router();

api.post(/^\/api\/register$/, async (context) => {
    const { request, env } = context;
    const { username, email, password } = await request.json();
    if (!username || !email || !password || !/^[a-zA-Z0-9_.-]+$/.test(username)) return new Response('Invalid request', { status: 400 });
    const userKey = `user:${username}`;
    if (await env.SINGFILE_KV.get(userKey)) return new Response('Username exists', { status: 409 });
    const salt = crypto.randomUUID();
    const passwordHash = await hashPassword(password, salt);
    await env.SINGFILE_KV.put(userKey, JSON.stringify({ email, passwordHash, salt, verified: false }));
    const verificationToken = crypto.randomUUID();
    await env.SINGFILE_KV.put(`verify_token:${verificationToken}`, username, { expirationTtl: 86400 });
    await sendVerificationEmail(context, email, username, verificationToken);
    return new Response('Registration successful. Please check your email.', { status: 201 });
});

api.get(/^\/api\/verify\/(?<token>[^/]+)$/, async ({ env, params }) => {
    const tokenKey = `verify_token:${params.token}`;
    const username = await env.SINGFILE_KV.get(tokenKey);
    if (!username) return new Response('Invalid or expired token', { status: 400 });
    const userKey = `user:${username}`;
    const userDataJSON = await env.SINGFILE_KV.get(userKey);
    if (!userDataJSON) return new Response('User not found', { status: 404 });
    const userData = JSON.parse(userDataJSON);
    userData.verified = true;
    await env.SINGFILE_KV.put(userKey, JSON.stringify(userData));
    await env.SINGFILE_KV.delete(tokenKey);
    return new Response('Email verified successfully! You can now log in.', { status: 200 });
});

api.post(/^\/api\/login$/, async ({ request, env }) => {
    const { username, password } = await request.json();
    const userKey = `user:${username}`;
    const userDataJSON = await env.SINGFILE_KV.get(userKey);
    if (!userDataJSON) return new Response('Invalid credentials', { status: 401 });
    const userData = JSON.parse(userDataJSON);
    if (!userData.verified) return new Response('Account not verified', { status: 403 });
    const passwordHash = await hashPassword(password, userData.salt);
    if (passwordHash !== userData.passwordHash) return new Response('Invalid credentials', { status: 401 });
    const payload = { username, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 };
    const token = await createJwt(payload, env.JWT_SECRET);
    return new Response(JSON.stringify({ token }), { headers: { 'Content-Type': 'application/json' } });
});

api.get(/^\/api\/repos$/, async (context) => {
    const auth = await authMiddleware(context); if (auth) return auth;
    const { env, user } = context;
    const list = await env.SINGFILE_KV.list({ prefix: `repo:${user.username}:` });
    return new Response(JSON.stringify(list.keys.map(k => ({ name: k.name.substring(`repo:${user.username}:`.length) }))), { headers: { 'Content-Type': 'application/json' } });
});

api.post(/^\/api\/repos$/, async (context) => {
    const auth = await authMiddleware(context); if (auth) return auth;
    const { env, user, request } = context;
    const { reponame, content } = await request.json();
    if (!reponame || content == null || !/^[a-zA-Z0-9_.-]+$/.test(reponame)) return new Response('Invalid request', { status: 400 });
    const repoKey = `repo:${user.username}:${reponame}`;
    if (await env.SINGFILE_KV.get(repoKey)) return new Response(`Repo "${reponame}" exists`, { status: 409 });
    await env.SINGFILE_KV.put(repoKey, content);
    await env.SINGFILE_KV.put(`history:${user.username}:${reponame}:${Date.now()}`, content);
    return new Response(JSON.stringify({ message: 'Repo created' }), { status: 201 });
});

api.get(/^\/api\/repos\/(?<reponame>[^/]+)$/, async (context) => {
    const auth = await authMiddleware(context); if (auth) return auth;
    const { env, user, params } = context;
    const content = await env.SINGFILE_KV.get(`repo:${user.username}:${params.reponame}`);
    if (content === null) return new Response('Repo not found', { status: 404 });
    return new Response(JSON.stringify({ name: params.reponame, content }), { headers: { 'Content-Type': 'application/json' } });
});

api.put(/^\/api\/repos\/(?<reponame>[^/]+)$/, async (context) => {
    const auth = await authMiddleware(context); if (auth) return auth;
    const { env, user, request, params } = context;
    const { content } = await request.json();
    if (content == null) return new Response('Content is required', { status: 400 });
    const repoKey = `repo:${user.username}:${params.reponame}`;
    if (await env.SINGFILE_KV.get(repoKey) === null) return new Response('Repo not found', { status: 404 });
    await env.SINGFILE_KV.put(repoKey, content);
    await env.SINGFILE_KV.put(`history:${user.username}:${params.reponame}:${Date.now()}`, content);
    return new Response(JSON.stringify({ message: 'Repo updated' }), { status: 200 });
});

api.delete(/^\/api\/repos\/(?<reponame>[^/]+)$/, async (context) => {
    const auth = await authMiddleware(context); if (auth) return auth;
    const { env, user, params } = context;
    const list = await env.SINGFILE_KV.list({ prefix: `history:${user.username}:${params.reponame}:` });
    const keysToDelete = list.keys.map(key => key.name);
    keysToDelete.push(`repo:${user.username}:${params.reponame}`);
    // Batch delete in chunks of 25, the max for KV bulk delete
    for (let i = 0; i < keysToDelete.length; i += 25) {
        await Promise.all(keysToDelete.slice(i, i + 25).map(key => env.SINGFILE_KV.delete(key)));
    }
    return new Response(null, { status: 204 });
});

api.get(/^\/api\/repos\/download\/(?<reponame>[^/]+)$/, async (context) => {
    const auth = await authMiddleware(context); if (auth) return auth;
    const { env, user, params } = context;
    const vol = new Volume();
    const fs = vol.promises;
    const dir = `/`;
    await git.init({ fs, dir });
    const list = await env.SINGFILE_KV.list({ prefix: `history:${user.username}:${params.reponame}:` });
    if (list.keys.length === 0) return new Response("No history for this repo.", { status: 404 });
    const sortedKeys = list.keys.sort((a, b) => parseInt(a.name.split(':')[3], 10) - parseInt(b.name.split(':')[3], 10));
    for (const key of sortedKeys) {
        const timestamp = parseInt(key.name.split(':')[3], 10);
        const content = await env.SINGFILE_KV.get(key.name);
        await fs.writeFile(`${dir}/${params.reponame}`, content);
        await git.add({ fs, dir, filepath: params.reponame });
        await git.commit({ fs, dir, message: `Update at ${new Date(timestamp).toISOString()}`, author: { name: user.username, email: `${user.username}@singfile.local` } });
    }
    const zipData = {};
    const filesInRepo = await fs.readdir(dir);
    for(const file of filesInRepo) {
        if(file === '.git') {
            const gitDirFiles = await fs.readdir(`${dir}/.git`, { recursive: true });
            for(const gitFile of gitDirFiles) {
                const path = `${dir}/.git/${gitFile}`;
                if((await fs.stat(path)).isFile()) zipData[`.git/${gitFile}`] = await fs.readFile(path);
            }
        } else {
            zipData[file] = await fs.readFile(`${dir}/${file}`);
        }
    }
    return new Response(zipSync(zipData), { headers: { 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="${params.reponame}.git.zip"` } });
});

const fileViewRouter = Router();
fileViewRouter.get(/^\/(?<user>[^/]+)\/(?<file>[^/]+)$/, async ({ env, params, request }) => {
    const url = new URL(request.url);
    const download = url.searchParams.get('download') === 'true';
    const content = await env.SINGFILE_KV.get(`repo:${params.user}:${params.file}`);
    if (content === null) return new Response('File not found.', { status: 404 });
    if (download) return new Response(content, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': `attachment; filename="${params.file}"` } });
    const html = `<!DOCTYPE html><html><head><title>${params.file}</title><link href="/style.css" rel="stylesheet"></head><body><div class="container"><header><h1>singfile</h1><nav><a href="/">Home</a></nav></header><main class="file-view"><h2>${params.file}</h2><p class="author">by ${params.user}</p><a href="?download=true" class="button">Download</a><pre class="file-content">${content.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</pre></main></div></body></html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html' } });
});

export async function onRequest(context) {
    const url = new URL(context.request.url);
    if (url.pathname.startsWith('/api/')) return api.route(context);
    const isStaticAsset = /\.(css|js|png|jpg|jpeg|gif|ico|svg)$/.test(url.pathname);
    const pathParts = url.pathname.split('/').filter(p => p);
    if (pathParts.length === 2 && !isStaticAsset) return fileViewRouter.route(context);
    return context.env.ASSETS.fetch(context.request);
}