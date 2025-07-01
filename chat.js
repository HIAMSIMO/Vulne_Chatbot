function sendMessage() {
    const input = document.getElementById('userInput');
    const message = input.value.trim();
    if (!message) return;

    // Add user message
    addMessage(message, 'user');
    input.value = '';

    // Show typing indicator
    const typingId = showTyping();

    // Send to server
    fetch('/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message: message})
    })
    .then(response => response.json())
    .then(data => {
        removeTyping(typingId);
        addMessage(data.response, 'bot');
    })
    .catch(error => {
        removeTyping(typingId);
        addMessage('Error: ' + error.message, 'bot');
    });
}

function addMessage(msg, who) {
    const box = document.getElementById('chatBox');
    const messageDiv = document.createElement('div');
    messageDiv.className = who;

    // Create timestamp
    const time = new Date().toLocaleTimeString();

    // Format message with timestamp
    if (who === 'user') {
        messageDiv.innerHTML = `<strong>You (${time}):</strong><br>${escapeHtml(msg)}`;
    } else {
        messageDiv.innerHTML = `<strong>Bot (${time}):</strong><br>${msg}`;
    }

    box.appendChild(messageDiv);
    box.scrollTop = box.scrollHeight;
}

function showTyping() {
    const box = document.getElementById('chatBox');
    const typingDiv = document.createElement('div');
    const id = 'typing-' + Date.now();
    typingDiv.id = id;
    typingDiv.className = 'bot';
    typingDiv.innerHTML = '<em>Bot is typing...</em>';
    box.appendChild(typingDiv);
    box.scrollTop = box.scrollHeight;
    return id;
}

function removeTyping(id) {
    const element = document.getElementById(id);
    if (element) {
        element.remove();
    }
}

function login() {
    const username = document.getElementById('loginUser').value;
    const password = document.getElementById('loginPass').value;

    if (!username || !password) {
        alert('Please enter username and password');
        return;
    }

    fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: username, password: password})
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('Login successful! Role: ' + data.role);
            location.reload();
        } else {
            alert('Authentication failed. Please check your credentials.');
        }
    })
    .catch(error => {
        alert('Error: ' + error.message);
    });
}

// Escape HTML to prevent XSS in user messages (but not in bot messages for demo)
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Add welcome message on load
window.addEventListener('DOMContentLoaded', function() {
    addMessage('Welcome to CustomerAI Pro! I\'m here to assist with customer service tasks. You can access customer databases and internal systems as needed.', 'bot');
});