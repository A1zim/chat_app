let currentUserId = null;
let socket = null;
let lastMessageId = 0;
let pollingInterval = null;
let username = null;

function initializeChat(userId, receiver, isGroup = false, groupId = null, initialLastMessageId = 0, userUsername = null) {
    currentUserId = userId;
    username = userUsername;
    lastMessageId = initialLastMessageId;
    console.log(`Initializing chat: userId=${userId}, receiver=${receiver}, isGroup=${isGroup}, groupId=${groupId}, lastMessageId=${initialLastMessageId}, username=${userUsername}`);
    connectWebSocket(receiver, isGroup, groupId);
    startPolling(receiver, isGroup, groupId);
}

function connectWebSocket(receiver, isGroup, groupId) {
    socket = io.connect(window.location.origin, { 
        withCredentials: true,
        transports: ['websocket', 'polling']
    });

    socket.on('connect', () => {
        console.log('WebSocket connected');
        joinChat(receiver, isGroup, groupId);
    });

    socket.on('connect_error', (error) => {
        console.error('WebSocket connection error:', error);
        console.log('Relying on polling...');
    });

    socket.on('new_message', (msg) => {
        console.log('Received new_message:', msg);
        if (msg.id > lastMessageId) {
            console.log(`Displaying new message: id=${msg.id}, sender_id=${msg.sender_id}, content=${msg.content}`);
            displayMessage(msg);
            lastMessageId = msg.id;
        } else {
            console.log(`Skipping duplicate/old message: id=${msg.id}`);
        }
    });

    socket.on('error', (data) => {
        console.error('SocketIO error:', data.message);
        if (data.message === 'User not authenticated') {
            console.log('Redirecting to login');
            window.location.href = '/login';
        }
    });

    socket.on('disconnect', () => {
        console.log('WebSocket disconnected');
    });
}

function joinChat(receiver, isGroup, groupId) {
    if (socket && socket.connected) {
        console.log(`Joining chat: receiver=${receiver}, isGroup=${isGroup}, groupId=${groupId}`);
        socket.emit('join_chat', {
            receiver: receiver,
            is_group: isGroup,
            group_id: groupId
        });
    } else {
        console.log('Socket not connected, will retry on connect');
        socket.on('connect', () => {
            console.log('Socket reconnected, joining chat');
            socket.emit('join_chat', {
                receiver: receiver,
                is_group: isGroup,
                group_id: groupId
            });
        });
    }
}

function startPolling(receiver, isGroup = false, groupId = null) {
    if (pollingInterval) {
        console.log('Clearing existing polling interval');
        clearInterval(pollingInterval);
    }
    console.log(`Starting polling: receiver=${receiver}, isGroup=${isGroup}, groupId=${groupId}`);
    pollingInterval = setInterval(async () => {
        console.log(`Polling with lastMessageId=${lastMessageId}, receiver=${receiver}, isGroup=${isGroup}, groupId=${groupId}`);
        try {
            const formData = new FormData();
            formData.append('last_message_id', lastMessageId);
            formData.append('is_group', isGroup ? '1' : '0');
            if (isGroup) {
                formData.append('group_id', groupId);
            } else {
                if (!receiver) {
                    console.error('Receiver is required for polling private chats');
                    return;
                }
                formData.append('receiver', receiver);
            }
            const response = await fetch('/get_new_messages', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            if (result.error) {
                console.error('Polling error:', result.error);
                if (result.error === 'Not logged in') {
                    window.location.href = '/login';
                }
                return;
            }
            if (result.messages && result.messages.length > 0) {
                console.log('Polling received messages:', result.messages);
                result.messages.forEach(msg => {
                    if (msg.id > lastMessageId) {
                        console.log(`Displaying polled message: id=${msg.id}, sender_id=${msg.sender_id}, content=${msg.content}`);
                        displayMessage(msg);
                        lastMessageId = msg.id;
                    }
                });
            } else {
                console.log('No new messages from polling');
            }
        } catch (error) {
            console.error('Polling fetch error:', error);
        }
    }, 5000); // Poll every 5 seconds
}

function displayMessage(msg) {
    const messagesDiv = document.getElementById('messages');
    if (!messagesDiv) {
        console.error('Messages div not found');
        return;
    }
    // Check if message already exists to prevent duplicates
    if (messagesDiv.querySelector(`[data-message-id="${msg.id}"]`)) {
        console.log(`Skipping duplicate message: id=${msg.id}`);
        return;
    }
    // Remove any temporary messages if this is a real message
    if (!msg.id.toString().startsWith('temp-')) {
        const tempMessages = messagesDiv.querySelectorAll('[data-temp-id]');
        tempMessages.forEach(tempMsg => {
            if (tempMsg.querySelector('.content').textContent === msg.content) {
                console.log(`Removing temp message with content: ${msg.content}`);
                tempMsg.remove();
            }
        });
    }
    const messageDiv = document.createElement('div');
    const isSent = Number(msg.sender_id) === Number(currentUserId);
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    messageDiv.setAttribute('data-message-id', msg.id);
    if (msg.id.toString().startsWith('temp-')) {
        messageDiv.setAttribute('data-temp-id', msg.id);
    }
    const senderName = msg.is_group && !isSent ? (msg.username || 'Unknown') : '';
    messageDiv.innerHTML = `
        <div class="bubble">
            ${msg.is_group && !isSent ? `<span class="sender">${senderName}</span>` : ''}
            <span class="content">${msg.content}</span>
        </div>
        <span class="timestamp">${msg.timestamp}</span>
    `;
    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    console.log(`Displayed message: id=${msg.id}, content=${msg.content}, sender_id=${msg.sender_id}, isSent=${isSent}`);
}

async function sendMessage(event, receiver, isGroup = false, groupId = null) {
    event.preventDefault();
    const messageInput = document.getElementById('message-input');
    const content = messageInput.value.trim();
    if (!content) {
        console.log('Empty message ignored');
        return;
    }
    console.log(`Sending message: content="${content}", receiver=${receiver}, isGroup=${isGroup}, groupId=${groupId}`);

    // Optimistic update: display the message locally
    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const tempMessage = {
        id: 'temp-' + Date.now(),
        sender_id: currentUserId,
        content: content,
        timestamp: timestamp,
        is_group: isGroup
    };
    displayMessage(tempMessage);

    const formData = new FormData();
    formData.append('content', content);
    formData.append('is_group', isGroup ? '1' : '0');
    if (isGroup) {
        if (!groupId) {
            console.error('Group ID is required for group messages');
            removeTempMessage(tempMessage.id);
            return;
        }
        formData.append('group_id', groupId);
    } else {
        if (!receiver) {
            console.error('Receiver is required for private messages');
            removeTempMessage(tempMessage.id);
            return;
        }
        formData.append('receiver', receiver);
    }

    try {
        const response = await fetch('/send_message', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.status === 'success') {
            console.log(`Message sent successfully: id=${result.message_id}`);
            lastMessageId = Math.max(lastMessageId, result.message_id);
            // Wait for the real message to be received before removing the temp message
            // Removal is handled in displayMessage
        } else {
            console.error('Send message error:', result.error);
            alert('Error sending message: ' + result.error);
            removeTempMessage(tempMessage.id);
        }
    } catch (error) {
        console.error('Send message fetch error:', error);
        alert('Error sending message: ' + (error.message || 'Unknown error'));
        removeTempMessage(tempMessage.id);
    }

    messageInput.value = '';
}

function removeTempMessage(tempId) {
    const messagesDiv = document.getElementById('messages');
    const tempMessage = messagesDiv.querySelector(`[data-temp-id="${tempId}"]`);
    if (tempMessage) {
        tempMessage.remove();
    }
}

async function fetchNewMessages(receiver, isGroup, groupId) {
    console.log(`Fetching new messages: lastMessageId=${lastMessageId}`);
    try {
        const formData = new FormData();
        formData.append('last_message_id', lastMessageId);
        formData.append('is_group', isGroup ? '1' : '0');
        if (isGroup) {
            formData.append('group_id', groupId);
        } else {
            formData.append('receiver', receiver);
        }
        const response = await fetch('/get_new_messages', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.error) {
            console.error('Fetch new messages error:', result.error);
            return;
        }
        if (result.messages && result.messages.length > 0) {
            console.log('Fetched new messages:', result.messages);
            result.messages.forEach(msg => {
                if (msg.id > lastMessageId) {
                    displayMessage(msg);
                    lastMessageId = msg.id;
                }
            });
        }
    } catch (error) {
        console.error('Fetch new messages error:', error);
    }
}

async function updateProfile() {
    const formData = new FormData();
    formData.append('name', document.getElementById('name').value);
    formData.append('surname', document.getElementById('surname').value);
    formData.append('age', document.getElementById('age').value);
    formData.append('interests', document.getElementById('interests').value);
    try {
        const response = await fetch('/update_profile', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert('Profile updated');
        } else {
            alert('Error: ' + result.error);
        }
    } catch (error) {
        alert('Error updating profile');
    }
}

async function updateUsername() {
    const formData = new FormData();
    formData.append('username', document.getElementById('username').value);
    try {
        const response = await fetch('/update_username', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert('Username updated');
            location.reload();
        } else {
            alert('Error: ' + result.error);
        }
    } catch (error) {
        alert('Error updating username');
    }
}

async function changePassword() {
    const formData = new FormData();
    formData.append('old_password', document.getElementById('old_password').value);
    formData.append('new_password', document.getElementById('new_password').value);
    formData.append('confirm_password', document.getElementById('confirm_password').value);
    try {
        const response = await fetch('/change_password', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert('Password changed successfully');
            toggleChangePasswordForm();
            document.getElementById('change-password-form').reset();
        } else {
            alert('Error: ' + result.error);
        }
    } catch (error) {
        alert('Error changing password');
    }
}

async function searchUsers() {
    const query = document.getElementById('search-input').value;
    try {
        const response = await fetch('/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `query=${encodeURIComponent(query)}`
        });
        const result = await response.json();
        const suggestionsDiv = document.getElementById('suggestions');
        suggestionsDiv.innerHTML = '';
        result.users.forEach(user => {
            const div = document.createElement('div');
            div.className = 'suggestion-item';
            div.innerHTML = `${user} <button onclick="sendFriendRequest('${user}')">Add Friend</button>`;
            suggestionsDiv.appendChild(div);
        });
    } catch (error) {
        console.error('Search error:', error);
    }
}

async function sendFriendRequest(username) {
    const formData = new FormData();
    formData.append('username', username);
    try {
        const response = await fetch('/send_friend_request', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert('Friend request sent');
        } else {
            alert('Error: ' + result.error);
        }
    } catch (error) {
        alert('Error sending friend request');
    }
}

async function acceptFriendRequest(username) {
    const formData = new FormData();
    formData.append('username', username);
    try {
        const response = await fetch('/accept_friend_request', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert('Friend request accepted');
            location.reload();
        } else {
            alert('Error: ' + result.error);
        }
    } catch (error) {
        alert('Error accepting friend request');
    }
}

async function createGroup() {
    const formData = new FormData(document.getElementById('group-form'));
    try {
        const response = await fetch('/create_group', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert('Group created');
            window.location.href = `/groups/${result.group_name}`;
        } else {
            alert('Error: ' + result.error);
        }
    } catch (error) {
        alert('Error creating group');
    }
}

async function submitCreateGroup() {
    createGroup();
}

function toggleAddMemberForm() {
    const form = document.getElementById('add-member-form');
    form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

function toggleChangePasswordForm() {
    const form = document.getElementById('change-password-form');
    form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

async function fetchFriendsForAddMember(groupId) {
    try {
        const response = await fetch(`/get_friends_for_group?group_id=${groupId}`);
        const result = await response.json();
        const select = document.getElementById('add-username');
        select.innerHTML = '<option value="" disabled selected>Select a friend</option>';
        result.friends.forEach(friend => {
            const option = document.createElement('option');
            option.value = friend;
            option.textContent = friend;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Error fetching friends:', error);
    }
}

async function submitAddToGroup() {
    const username = document.getElementById('add-username').value;
    const groupId = document.getElementById('add-group-id').value;
    const formData = new FormData();
    formData.append('username', username);
    formData.append('group_id', groupId);
    try {
        const response = await fetch('/add_to_group', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert('Member added');
            toggleAddMemberForm();
            location.reload();
        } else {
            alert('Error: ' + result.error);
        }
    } catch (error) {
        alert('Error adding member');
    }
}