const API_BASE = '/api';
const TOKEN_KEY = 'singfile_token';

document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;

    if (path === '/' || path === '/index.html') {
        initIndexPage();
    } else if (path === '/dashboard.html') {
        initDashboardPage();
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
    el.textContent = text;
    el.className = isError ? 'message error' : 'message success';
}

// --- INDEX PAGE LOGIC ---

function initIndexPage() {
    // If user is already logged in, redirect to dashboard
    if (getAuthToken()) {
        window.location.href = '/dashboard.html';
        return;
    }
    
    const registerForm = document.getElementById('register-form');
    const loginForm = document.getElementById('login-form');

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
            if (!response.ok) {
                throw new Error(responseText);
            }
            displayMessage(messageEl, responseText, false);
            registerForm.reset();
        } catch (err) {
            displayMessage(messageEl, err.message, true);
        }
    });

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
            window.location.href = '/dashboard.html';
        } catch (err) {
            displayMessage(messageEl, err.message, true);
        }
    });
}


// --- DASHBOARD PAGE LOGIC ---

function initDashboardPage() {
    const token = getAuthToken();
    if (!token) {
        window.location.href = '/index.html';
        return;
    }

    const logoutBtn = document.getElementById('logout-btn');
    const fileForm = document.getElementById('file-form');
    const welcomeUser = document.getElementById('welcome-user');
    const cancelEditBtn = document.getElementById('cancel-edit-btn');
    
    // Decode username from JWT for display
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        welcomeUser.textContent = `Welcome, ${payload.username}`;
    } catch(e) {
        console.error("Could not parse JWT for username");
        clearAuthToken();
        window.location.href = '/index.html';
    }

    logoutBtn.addEventListener('click', () => {
        clearAuthToken();
        window.location.href = '/index.html';
    });
    
    cancelEditBtn.addEventListener('click', () => resetFileForm());

    loadFiles();

    fileForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(fileForm);
        const content = formData.get('content');
        const filename = formData.get('filename');
        const editModeFilename = document.getElementById('edit-mode-filename').value;
        const messageEl = 'file-message';

        const isEditing = !!editModeFilename;
        const url = isEditing ? `${API_BASE}/files/${editModeFilename}` : `${API_BASE}/files`;
        const method = isEditing ? 'PUT' : 'POST';

        try {
            const response = await fetch(url, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ filename, content }),
            });
            const responseText = await response.text();
             if (!response.ok) {
                throw new Error(responseText);
            }
            displayMessage(messageEl, isEditing ? 'File updated successfully!' : 'File created successfully!', false);
            resetFileForm();
            loadFiles();
        } catch (err) {
            displayMessage(messageEl, err.message, true);
        }
    });
}

async function loadFiles() {
    const token = getAuthToken();
    const fileList = document.getElementById('file-list');
    fileList.innerHTML = '<li>Loading...</li>';

    try {
        const response = await fetch(`${API_BASE}/files`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) throw new Error('Failed to fetch files');
        const files = await response.json();

        fileList.innerHTML = '';
        if (files.length === 0) {
            fileList.innerHTML = '<li>You have no files yet. Create one above!</li>';
        } else {
            files.forEach(file => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span>
                        <a href="${file.url}" target="_blank">${file.name}</a>
                    </span>
                    <span class="file-actions">
                        <button class="button-link" onclick="editFile('${file.name}')">Edit</button>
                        <button class="button-link" onclick="deleteFile('${file.name}')">Delete</button>
                    </span>
                `;
                fileList.appendChild(li);
            });
        }
    } catch (err) {
        fileList.innerHTML = `<li>Error: ${err.message}</li>`;
    }
}

async function editFile(filename) {
    const token = getAuthToken();
    try {
        const response = await fetch(`${API_BASE}/files/${filename}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) throw new Error('Failed to load file content.');

        const file = await response.json();
        document.getElementById('form-title').textContent = `Editing: ${file.filename}`;
        document.getElementById('filename').value = file.filename;
        document.getElementById('filename').readOnly = true; // Don't allow renaming
        document.getElementById('content').value = file.content;
        document.getElementById('edit-mode-filename').value = file.filename;
        document.getElementById('save-btn').textContent = 'Save Changes';
        document.getElementById('cancel-edit-btn').style.display = 'inline-block';
        window.scrollTo(0, 0);

    } catch(err) {
        displayMessage('file-message', err.message, true);
    }
}

async function deleteFile(filename) {
    if (!confirm(`Are you sure you want to delete ${filename}? This cannot be undone.`)) {
        return;
    }
    const token = getAuthToken();
    try {
        const response = await fetch(`${API_BASE}/files/${filename}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
         if (!response.ok) {
            const responseText = await response.text();
            throw new Error(responseText || 'Failed to delete file.');
        }
        loadFiles();
    } catch(err) {
        displayMessage('file-message', err.message, true);
    }
}

function resetFileForm() {
    document.getElementById('file-form').reset();
    document.getElementById('form-title').textContent = 'Create New File';
    document.getElementById('filename').readOnly = false;
    document.getElementById('edit-mode-filename').value = '';
    document.getElementById('save-btn').textContent = 'Save File';
    document.getElementById('cancel-edit-btn').style.display = 'none';
    document.getElementById('file-message').textContent = '';
}

// Make editFile and deleteFile globally accessible from the inline onclick handlers
window.editFile = editFile;
window.deleteFile = deleteFile;