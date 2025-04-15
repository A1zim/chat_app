let lastMessageId = 0;
let currentUserId = null;

function initializeChat(userId, initialLastMessageId) {
    currentUserId = userId;
    lastMessageId = initialLastMessageId;
}

function sendMessage(isGroup = false, groupId = null) {
    const content = document.getElementById('message-input').value;
    const receiver = document.getElementById('receiver')?.value;
    if (!content) return;
    fetch('/send_message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `receiver=${receiver}&content=${content}&is_group=${isGroup ? 1 : 0}${groupId ? `&group_id=${groupId}` : ''}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const messages = document.querySelector('.messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message sent';
            messageDiv.innerHTML = `<div class="bubble">${content}</div><span class="time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>`;
            messages.appendChild(messageDiv);
            messages.scrollTop = messages.scrollHeight;
            document.getElementById('message-input').value = '';
            lastMessageId = data.message_id;  // Update the last message ID
        }
    })
    .catch(error => console.error('Error sending message:', error));
}

function pollForMessages(isGroup = false, groupId = null) {
    const receiver = document.getElementById('receiver')?.value;
    fetch('/get_new_messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `last_message_id=${lastMessageId}&receiver=${receiver}&is_group=${isGroup ? 1 : 0}${groupId ? `&group_id=${groupId}` : ''}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.messages && data.messages.length > 0) {
            const messages = document.querySelector('.messages');
            data.messages.forEach(msg => {
                const messageDiv = document.createElement('div');
                const isSent = msg.sender_id == currentUserId;
                messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
                messageDiv.innerHTML = `<div class="bubble">${msg.content}</div><span class="time">${msg.timestamp}</span>`;
                messages.appendChild(messageDiv);
                lastMessageId = msg.id;  // Update the last message ID
            });
            messages.scrollTop = messages.scrollHeight;
        }
    })
    .catch(error => console.error('Error polling for messages:', error));
}

function startPolling(isGroup = false, groupId = null) {
    setInterval(() => pollForMessages(isGroup, groupId), 5000);  // Poll every 5 seconds
}

function createGroup() {
    const groupName = prompt('Enter group name:');
    if (!groupName) return;
    fetch('/create_group', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `group_name=${groupName}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            window.location.href = `/groups/${data.group_name}`;
        }
    })
    .catch(error => console.error('Error creating group:', error));
}

function updateProfile() {
    const name = document.getElementById('name').value;
    const surname = document.getElementById('surname').value;
    const age = document.getElementById('age').value;
    const interests = document.getElementById('interests').value;
    fetch('/update_profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `name=${name}&surname=${surname}&age=${age}&interests=${interests}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('Profile updated successfully');
        }
    })
    .catch(error => console.error('Error updating profile:', error));
}

function updateAccount() {
    const email = document.getElementById('email').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    fetch('/update_account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `email=${email}&username=${username}&password=${password}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('Account updated successfully');
        } else {
            alert(data.error);
        }
    })
    .catch(error => console.error('Error updating account:', error));
}

function searchUsers() {
    const query = document.getElementById('search-input').value;
    if (!query) {
        document.getElementById('suggestions').innerHTML = '';
        return;
    }
    fetch('/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `query=${query}`
    })
    .then(response => response.json())
    .then(data => {
        const suggestions = document.getElementById('suggestions');
        suggestions.innerHTML = '';
        data.users.forEach(user => {
            const div = document.createElement('div');
            div.className = 'suggestion-item';
            div.innerHTML = `
                <span>${user}</span>
                <button onclick="sendFriendRequest('${user}')">Add Friend</button>
            `;
            suggestions.appendChild(div);
        });
    })
    .catch(error => console.error('Error searching users:', error));
}

function sendFriendRequest(username) {
    fetch('/send_friend_request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=${username}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert(`Friend request sent to ${username}`);
        } else {
            alert(data.error);
        }
    })
    .catch(error => console.error('Error sending friend request:', error));
}

function acceptFriendRequest(username) {
    fetch('/accept_friend_request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=${username}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert(`Friend request from ${username} accepted`);
            location.reload();
        } else {
            alert(data.error);
        }
    })
    .catch(error => console.error('Error accepting friend request:', error));
}