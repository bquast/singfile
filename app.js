const API_BASE = '/api';
const TOKEN_KEY = 'singfile_token';

// Helper function to safely decode a Base64Url string
function safeBase64UrlDecode(str) {
    try {
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const padding = base64.length % 4;
        if (padding) {
            base64 += '===='.slice(padding);
        }
        return atob(base64);
    } catch (e) {
        console.error("Base64Url decoding failed:", e);
        return null;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;
    if (path.includes('dashboard')) {
        initDashboardPage();
    } else {
        initIndexPage();
    }
});

function getAuthToken() {
    return localStorage.getItem(TOKEN_KEY);
}

function setAuthToken(token) {
    localStorage.setItem(TOKEN_KEY, token);
}

function clearAuthToken() {
    localStorage.removeItem(TOKEN_KEY);
}

function displayMessage(elementId, text, isError = false) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = text;
    el.className = isError ? 'message error' : 'message success';
}

function initIndexPage() {
    if (getAuthToken()) {
        window.location.href = '/dashboard';
        return;
    }
    
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(registerForm);
            const data = Object.fromEntries(formData.entries());
            const messageEl = 'register-message';
            try {
                const response = await fetch(`${API_BASE}/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });
                const responseText = await response.text();
                if (!response.ok) throw new Error(responseText);
                displayMessage(messageEl, responseText, false);
                registerForm.reset();
            } catch (err) {
                displayMessage(messageEl, err.message, true);
            }
        });
    }

    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            const data = Object.fromEntries(formData.entries());
            const messageEl = 'login-message';
            try {
                const response = await fetch(`${API_BASE}/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });
                if (!response.ok) {
                     const responseText = await response.text();
                     throw new Error(responseText || 'Login failed');
                }
                const { token } = await response.json();
                setAuthToken(token);
                window.location.href = '/dashboard';
            } catch (err) {
                displayMessage(messageEl, err.message, true);
            }
        });
    }
}

function initDashboardPage() {
    const token = getAuthToken();
    if (!token) {
        window.location.href = '/';
        return;
    }

    const logoutBtn = document.getElementById('logout-btn');
    const repoForm = document.getElementById('repo-form');
    const welcomeUser = document.getElementById('welcome-user');
    const cancelEditBtn = document.getElementById('cancel-edit-btn');
    
    try {
        const payloadStr = safeBase64UrlDecode(token.split('.')[1]);
        if (!payloadStr) throw new Error("Invalid token payload");
        const payload = JSON.parse(payloadStr);
        welcomeUser.textContent = `Welcome, ${payload.username}`;
    } catch(e) {
        console.error("Could not parse JWT:", e);
        clearAuthToken();
        window.location.href = '/';
        return;
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            clearAuthToken();
            window.location.href = '/';
        });
    }
    
    if (cancelEditBtn) {
        cancelEditBtn.addEventListener('click', () => resetRepoForm());
    }

    loadRepos();

    if (repoForm) {
        repoForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(repoForm);
            const content = formData.get('content');
            const reponame = formData.get('reponame');
            const editModeReponame = document.getElementById('edit-mode-reponame').value;
            const messageEl = 'repo-message';

            const isEditing = !!editModeReponame;
            const url = isEditing ? `${API_BASE}/repos/${editModeReponame}` : `${API_BASE}/repos`;
            const method = isEditing ? 'PUT' : 'POST';

            try {
                const response = await fetch(url, {
                    method,
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                    body: JSON.stringify({ reponame, content }),
                });
                const responseText = await response.text();
                if (!response.ok) throw new Error(responseText);
                displayMessage(messageEl, isEditing ? 'Repo updated successfully!' : 'Repo created successfully!', false);
                resetRepoForm();
                loadRepos();
            } catch (err) {
                displayMessage(messageEl, err.message, true);
            }
        });
    }
}

async function loadRepos() {
    const token = getAuthToken();
    const repoList = document.getElementById('repo-list');
    if (!repoList) return;
    repoList.innerHTML = '<li>Loading...</li>';

    try {
        const response = await fetch(`${API_BASE}/repos`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (!response.ok) throw new Error('Failed to fetch repos');
        const repos = await response.json();

        repoList.innerHTML = '';
        if (repos.length === 0) {
            repoList.innerHTML = '<li>You have no repos yet. Create one above!</li>';
        } else {
            const username = JSON.parse(safeBase64UrlDecode(token.split('.')[1])).username;
            repos.forEach(repo => {
                const li = document.createElement('li');
                const publicUrl = `/${username}/${repo.name}`;
                li.innerHTML = `
                    <span>
                        <a href="${publicUrl}" target="_blank">${repo.name}</a>
                    </span>
                    <span class="file-actions">
                        <a href="/api/repos/download/${repo.name}" class="button-link">Download</a>
                        <button class="button-link" onclick="editRepo('${repo.name}')">Edit</button>
                        <button class="button-link" onclick="deleteRepo('${repo.name}')">Delete</button>
                    </span>
                `;
                repoList.appendChild(li);
            });
        }
    } catch (err) {
        repoList.innerHTML = `<li>Error: ${err.message}</li>`;
    }
}

async function editRepo(reponame) {
    const token = getAuthToken();
    try {
        const response = await fetch(`${API_BASE}/repos/${reponame}`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (!response.ok) throw new Error('Failed to load repo content.');

        const repo = await response.json();
        document.getElementById('form-title').textContent = `Editing: ${repo.name}`;
        document.getElementById('reponame').value = repo.name;
        document.getElementById('reponame').readOnly = true;
        document.getElementById('content').value = repo.content;
        document.getElementById('edit-mode-reponame').value = repo.name;
        document.getElementById('save-btn').textContent = 'Save Changes';
        document.getElementById('cancel-edit-btn').style.display = 'inline-block';
        window.scrollTo(0, 0);

    } catch(err) {
        displayMessage('repo-message', err.message, true);
    }
}

async function deleteRepo(reponame) {
    if (!confirm(`Are you sure you want to delete the repo "${reponame}" and all its history?`)) return;
    
    const token = getAuthToken();
    try {
        const response = await fetch(`${API_BASE}/repos/${reponame}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) {
            const responseText = await response.text();
            throw new Error(responseText || 'Failed to delete repo.');
        }
        loadRepos();
    } catch(err) {
        displayMessage('repo-message', err.message, true);
    }
}

function resetRepoForm() {
    document.getElementById('repo-form')?.reset();
    document.getElementById('form-title')?.textContent = 'Create New Repo';
    const reponameInput = document.getElementById('reponame');
    if (reponameInput) reponameInput.readOnly = false;
    document.getElementById('edit-mode-reponame')?.setAttribute('value', '');
    document.getElementById('save-btn')?.textContent = 'Save Repo';
    const cancelBtn = document.getElementById('cancel-edit-btn');
    if (cancelBtn) cancelBtn.style.display = 'none';
    document.getElementById('repo-message')?.textContent = '';
}

window.editRepo = editRepo;
window.deleteRepo = deleteRepo;