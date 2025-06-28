let authToken = null;
let socket = null;
let currentUser = null;
let currentUserRole = null;
let mediaRecorder = null;
let audioChunks = [];
let isRecording = false;
let recordingStartTime = 0;
let recordingTimer = null;

const authSection = document.getElementById('auth-section');
const chatSection = document.getElementById('chat-section');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const registerBtn = document.getElementById('register-btn');
const loginBtn = document.getElementById('login-btn');
const googleLoginBtn = document.getElementById('google-login-btn');
const authMessage = document.getElementById('auth-message');
const currentUserSpan = document.getElementById('current-user');
const onlineUsersSpan = document.getElementById('online-users');

const searchUsersInput = document.getElementById('search-users');
const searchResultsDiv = document.getElementById('search-results');
const friendRequestsList = document.getElementById('friend-requests-list');
const friendsList = document.getElementById('friends-list');

const noChatSelected = document.getElementById('no-chat-selected');
const activeChat = document.getElementById('active-chat');
const chatPartnerSpan = document.getElementById('chat-partner');
const messagesDiv = document.getElementById('messages');
const messageInput = document.getElementById('message-input');
const sendMessageBtn = document.getElementById('send-message-btn');
const clearChatBtn = document.getElementById('clear-chat-btn');
const closeChatBtn = document.getElementById('close-chat-btn');
const logoutBtn = document.getElementById('logout-btn');

let currentChatPartner = null;
let rsaKeyPair = null;
let activeChatKeys = {};
let chatHistories = {};
let friendsData = {};
let keyExchangeInProgress = {};
let connectionRetries = 0;
const MAX_RETRIES = 3;

let selectedFile = null;
let currentPasswordForKeys = null;
let isGoogleUser = false;
let currentGroup = null;

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_SALT_STORAGE_KEY = 'chat-pbkdf2-salt';
const ENCRYPTED_RSA_PRIVATE_KEY_STORAGE_KEY = 'chat-encrypted-rsa-private-key-jwk';
const RSA_PUBLIC_KEY_PEM_STORAGE_KEY = 'chat-rsa-public-key-pem';
const ENCRYPTED_AES_KEYS_STORAGE_KEY = 'chat-encrypted-aes-keys-jwk';
const GOOGLE_USER_FLAG_KEY = 'chat-google-user-flag';
const GOOGLE_RSA_PRIVATE_KEY_STORAGE_KEY = 'chat-google-rsa-private-key-jwk';
const GOOGLE_AES_KEYS_STORAGE_KEY = 'chat-google-aes-keys-jwk';

if (typeof window.crypto === 'undefined' || typeof window.crypto.subtle === 'undefined') {
    console.error("Web Crypto API no disponible");
    alert("Tu navegador no soporta la API de Criptografía Web. La aplicación no funcionará correctamente.");
}

// --- Core Crypto Functions ---
async function generateRsaKeyPairInternal() {
    if (!window.crypto || !window.crypto.subtle) {
        throw new Error("crypto.subtle no disponible");
    }
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
}

async function exportPublicKeyAsPem(publicKey) {
    const spki = await window.crypto.subtle.exportKey("spki", publicKey);
    const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
    const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    return pem;
}

async function importPublicKeyFromPem(pem) {
    const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '');
    const binaryDer = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt", "wrapKey"]
    );
}

async function generateAesKey() {
    return window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptAes(text, key) {
    const encoded = new TextEncoder().encode(text);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encoded
    );
    return {
        encryptedMessage: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        iv: btoa(String.fromCharCode(...new Uint8Array(iv)))
    };
}

async function decryptAes(encryptedBase64, ivBase64, key) {
    try {
        const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            key,
            encrypted
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error("Error al descifrar:", e);
        return "[MENSAJE NO DESCIFRADO]";
    }
}

async function wrapAesKey(aesKeyToWrap, publicKeyRsa) {
    const wrappedKey = await window.crypto.subtle.wrapKey(
        "raw",
        aesKeyToWrap,
        publicKeyRsa,
        {
            name: "RSA-OAEP"
        }
    );
    return btoa(String.fromCharCode(...new Uint8Array(wrappedKey)));
}

async function unwrapAesKey(wrappedAesKeyBase64, privateKeyRsa) {
    const wrappedKey = Uint8Array.from(atob(wrappedAesKeyBase64), c => c.charCodeAt(0));
    return window.crypto.subtle.unwrapKey(
        "raw",
        wrappedKey,
        privateKeyRsa,
        {
            name: "RSA-OAEP",
        },
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptDataWithPasswordKey(dataString, passwordDerivedKey) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(dataString);
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        passwordDerivedKey,
        encodedData
    );
    return {
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        iv: btoa(String.fromCharCode(...new Uint8Array(iv)))
    };
}

async function decryptDataWithPasswordKey(encryptedDataObj, passwordDerivedKey) {
    const ciphertext = Uint8Array.from(atob(encryptedDataObj.ciphertext), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(encryptedDataObj.iv), c => c.charCodeAt(0));
    const decryptedArrayBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        passwordDerivedKey,
        ciphertext
    );
    return new TextDecoder().decode(decryptedArrayBuffer);
}

function getPbkdf2Salt(generateIfMissing = true) {
    let saltString = localStorage.getItem(PBKDF2_SALT_STORAGE_KEY);
    if (saltString) {
        return Uint8Array.from(atob(saltString), c => c.charCodeAt(0));
    } else if (generateIfMissing) {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        localStorage.setItem(PBKDF2_SALT_STORAGE_KEY, btoa(String.fromCharCode(...salt)));
        return salt;
    }
    return null;
}

// --- Funciones mejoradas para manejo de claves ---
async function saveKeysToLocalStorage(currentRsaKeyPair, currentPublicKeyPem, currentActiveChatKeys, password) {
    if (isGoogleUser) {
        const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", currentRsaKeyPair.privateKey);
        localStorage.setItem(GOOGLE_RSA_PRIVATE_KEY_STORAGE_KEY, JSON.stringify(privateKeyJwk));
        localStorage.setItem(RSA_PUBLIC_KEY_PEM_STORAGE_KEY, currentPublicKeyPem);
        localStorage.setItem(GOOGLE_USER_FLAG_KEY, 'true');

        const exportableActiveChatKeys = {};
        for (const user in currentActiveChatKeys) {
            if (currentActiveChatKeys[user] instanceof CryptoKey) {
                exportableActiveChatKeys[user] = await window.crypto.subtle.exportKey("jwk", currentActiveChatKeys[user]);
            }
        }
        localStorage.setItem(GOOGLE_AES_KEYS_STORAGE_KEY, JSON.stringify(exportableActiveChatKeys));
        console.log("Claves de usuario Google guardadas en localStorage.");
        return;
    }

    if (!password) {
        console.error("Password is required to save keys.");
        throw new Error("Password required for saving keys.");
    }
    let salt = getPbkdf2Salt(true);
    const passwordDerivedKey = await deriveKeyFromPassword(password, salt);

    const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", currentRsaKeyPair.privateKey);
    const encryptedRsaJwk = await encryptDataWithPasswordKey(JSON.stringify(privateKeyJwk), passwordDerivedKey);
    localStorage.setItem(ENCRYPTED_RSA_PRIVATE_KEY_STORAGE_KEY, JSON.stringify(encryptedRsaJwk));

    localStorage.setItem(RSA_PUBLIC_KEY_PEM_STORAGE_KEY, currentPublicKeyPem);
    localStorage.removeItem(GOOGLE_USER_FLAG_KEY);

    const exportableActiveChatKeys = {};
    for (const user in currentActiveChatKeys) {
        if (currentActiveChatKeys[user] instanceof CryptoKey) {
            exportableActiveChatKeys[user] = await window.crypto.subtle.exportKey("jwk", currentActiveChatKeys[user]);
        }
    }
    const encryptedAesKeys = await encryptDataWithPasswordKey(JSON.stringify(exportableActiveChatKeys), passwordDerivedKey);
    localStorage.setItem(ENCRYPTED_AES_KEYS_STORAGE_KEY, JSON.stringify(encryptedAesKeys));
    console.log("Claves de usuario normal guardadas en localStorage.");
}

async function loadKeysFromLocalStorage(password = null) {
    const isStoredGoogleUser = localStorage.getItem(GOOGLE_USER_FLAG_KEY) === 'true';
    
    if (isStoredGoogleUser || isGoogleUser) {
        const privateKeyJwkString = localStorage.getItem(GOOGLE_RSA_PRIVATE_KEY_STORAGE_KEY);
        const publicKeyPemString = localStorage.getItem(RSA_PUBLIC_KEY_PEM_STORAGE_KEY);
        const aesKeysString = localStorage.getItem(GOOGLE_AES_KEYS_STORAGE_KEY);

        if (!privateKeyJwkString || !publicKeyPemString) {
            console.log("Claves de usuario Google no encontradas.");
            return null;
        }

        try {
            const privateKeyJwk = JSON.parse(privateKeyJwkString);
            const privateKey = await window.crypto.subtle.importKey(
                "jwk",
                privateKeyJwk,
                { name: "RSA-OAEP", hash: "SHA-256" },
                true,
                ["decrypt", "unwrapKey"]
            );

            const loadedPublicKeyPem = publicKeyPemString;
            const publicKey = await importPublicKeyFromPem(loadedPublicKeyPem);
            const loadedRsaKeyPair = { privateKey, publicKey };

            let loadedActiveChatKeys = {};
            if (aesKeysString) {
                const activeChatKeysJwk = JSON.parse(aesKeysString);
                for (const user in activeChatKeysJwk) {
                    loadedActiveChatKeys[user] = await window.crypto.subtle.importKey(
                        "jwk",
                        activeChatKeysJwk[user],
                        { name: "AES-GCM" },
                        true,
                        ["encrypt", "decrypt"]
                    );
                }
            }

            console.log("Claves de usuario Google cargadas exitosamente.");
            return { rsaKeyPair: loadedRsaKeyPair, activeChatKeys: loadedActiveChatKeys, publicKeyPem: loadedPublicKeyPem };
        } catch (e) {
            console.error("Error cargando claves de usuario Google:", e);
            return null;
        }
    }

    if (!password) {
        console.error("Password is required to load keys for normal users.");
        return null;
    }
    
    const salt = getPbkdf2Salt(false);
    if (!salt) {
        console.log("No salt found. Assuming first login or cleared storage.");
        return null;
    }

    const passwordDerivedKey = await deriveKeyFromPassword(password, salt);

    const encryptedRsaJwkString = localStorage.getItem(ENCRYPTED_RSA_PRIVATE_KEY_STORAGE_KEY);
    const publicKeyPemString = localStorage.getItem(RSA_PUBLIC_KEY_PEM_STORAGE_KEY);
    const encryptedAesKeysString = localStorage.getItem(ENCRYPTED_AES_KEYS_STORAGE_KEY);

    if (!encryptedRsaJwkString || !publicKeyPemString) {
        console.log("Encrypted RSA key or Public Key PEM not found in localStorage.");
        return null;
    }

    let loadedRsaKeyPair;
    let loadedActiveChatKeys = {};
    let loadedPublicKeyPem;

    try {
        const encryptedRsaJwk = JSON.parse(encryptedRsaJwkString);
        const privateKeyJwkString = await decryptDataWithPasswordKey(encryptedRsaJwk, passwordDerivedKey);
        const privateKeyJwkParsed = JSON.parse(privateKeyJwkString);
        const privateKey = await window.crypto.subtle.importKey(
            "jwk",
            privateKeyJwkParsed,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt", "unwrapKey"]
        );

        loadedPublicKeyPem = publicKeyPemString;
        const publicKey = await importPublicKeyFromPem(loadedPublicKeyPem);
        loadedRsaKeyPair = { privateKey, publicKey };

        if (encryptedAesKeysString) {
            const encryptedAesKeys = JSON.parse(encryptedAesKeysString);
            const activeChatKeysJwkString = await decryptDataWithPasswordKey(encryptedAesKeys, passwordDerivedKey);
            const activeChatKeysJwk = JSON.parse(activeChatKeysJwkString);
            
            for (const user in activeChatKeysJwk) {
                loadedActiveChatKeys[user] = await window.crypto.subtle.importKey(
                    "jwk",
                    activeChatKeysJwk[user],
                    { name: "AES-GCM" },
                    true,
                    ["encrypt", "decrypt"]
                );
            }
        }
        console.log("Claves de usuario normal cargadas exitosamente.");
        return { rsaKeyPair: loadedRsaKeyPair, activeChatKeys: loadedActiveChatKeys, publicKeyPem: loadedPublicKeyPem };
    } catch (e) {
        console.error("Failed to load/decrypt keys from localStorage:", e);
        if (e.message.toLowerCase().includes("decryption failed") || e.name === "OperationError") {
            throw new Error("Failed to decrypt keys. Password may be incorrect or data corrupted.");
        }
        throw e;
    }
}

async function saveActiveChatKeysState() {
    if (rsaKeyPair && activeChatKeys) {
        try {
            const publicKeyPem = await exportPublicKeyAsPem(rsaKeyPair.publicKey);
            await saveKeysToLocalStorage(rsaKeyPair, publicKeyPem, activeChatKeys, currentPasswordForKeys);
            console.log("ActiveChatKeys state updated in localStorage.");
        } catch (error) {
            console.error("Error saving activeChatKeys state:", error);
        }
    }
}

// --- Funciones para determinar el rol de usuario y mostrar insignias ---
function getUserBadge(username, role) {
    if (username === 'admin@uni.edu.pe' || role === 'admin') {
        return '<span class="user-badge admin-badge">👑 Admin</span>';
    } else if (username.endsWith('@uni.edu.pe') || role === 'teacher') {
        return '<span class="user-badge teacher-badge">👨‍🏫 Docente</span>';
    } else if (username.endsWith('@uni.pe') || role === 'student') {
        return '<span class="user-badge student-badge">🎓 Alumno</span>';
    }
    return '<span class="user-badge student-badge">🎓 Alumno</span>';
}

function getRoleIcon(role) {
    switch (role) {
        case 'admin': return '👑';
        case 'teacher': return '👨‍🏫';
        case 'student': return '🎓';
        default: return '🎓';
    }
}

// --- Audio Recording Functions ---
async function startAudioRecording() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        
        mediaRecorder = new MediaRecorder(stream, {
            mimeType: MediaRecorder.isTypeSupported('audio/webm') ? 'audio/webm' : 'audio/mp4'
        });
        
        audioChunks = [];
        isRecording = true;
        recordingStartTime = Date.now();
        
        mediaRecorder.ondataavailable = (event) => {
            if (event.data.size > 0) {
                audioChunks.push(event.data);
            }
        };
        
        mediaRecorder.onstop = async () => {
            const audioBlob = new Blob(audioChunks, { 
                type: mediaRecorder.mimeType || 'audio/webm' 
            });
            
            const duration = Math.round((Date.now() - recordingStartTime) / 1000);
            await sendAudioMessage(audioBlob, duration);
            
            stream.getTracks().forEach(track => track.stop());
        };
        
        mediaRecorder.start();
        updateRecordingUI(true);
        startRecordingTimer();
        
    } catch (error) {
        console.error('Error iniciando grabación:', error);
        appendMessage('Sistema', 'Error: No se pudo acceder al micrófono', false, true);
    }
}

function stopAudioRecording() {
    if (mediaRecorder && isRecording) {
        mediaRecorder.stop();
        isRecording = false;
        updateRecordingUI(false);
        stopRecordingTimer();
    }
}

function cancelAudioRecording() {
    if (mediaRecorder && isRecording) {
        mediaRecorder.stop();
        isRecording = false;
        updateRecordingUI(false);
        stopRecordingTimer();
        
        audioChunks = [];
        
        if (mediaRecorder.stream) {
            mediaRecorder.stream.getTracks().forEach(track => track.stop());
        }
        
        appendMessage('Sistema', 'Grabación cancelada', false, true);
    }
}

function startRecordingTimer() {
    const timerDisplay = document.getElementById('recording-timer');
    recordingTimer = setInterval(() => {
        const elapsed = Math.round((Date.now() - recordingStartTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        timerDisplay.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }, 1000);
}

function stopRecordingTimer() {
    if (recordingTimer) {
        clearInterval(recordingTimer);
        recordingTimer = null;
    }
}

function updateRecordingUI(recording) {
    const recordBtn = document.getElementById('record-audio-btn');
    const recordingIndicator = document.getElementById('recording-indicator');
    const messageInputRow = document.querySelector('.message-input-row');
    
    if (recording) {
        recordBtn.style.display = 'none';
        recordingIndicator.style.display = 'flex';
        messageInputRow.style.display = 'none';
    } else {
        recordBtn.style.display = 'block';
        recordingIndicator.style.display = 'none';
        messageInputRow.style.display = 'flex';
        document.getElementById('recording-timer').textContent = '00:00';
    }
}

async function sendAudioMessage(audioBlob, duration) {
    if (!currentChatPartner || audioChunks.length === 0) return;
    
    if (!activeChatKeys[currentChatPartner]) {
        appendMessage('Sistema', `Conexión segura con ${currentChatPartner} no establecida.`, false, true);
        return;
    }
    
    try {
        appendMessage('Sistema', 'Procesando audio...', false, true);
        
        const arrayBuffer = await audioBlob.arrayBuffer();
        const base64Audio = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
        
        const audioInfo = {
            name: `audio_${Date.now()}.webm`,
            size: audioBlob.size,
            type: audioBlob.type || 'audio/webm',
            duration: duration
        };
        
        const audioInfoToEncrypt = JSON.stringify(audioInfo);
        const { encryptedMessage, iv } = await encryptAes(audioInfoToEncrypt, activeChatKeys[currentChatPartner]);
        
        const messageData = {
            receiver: currentChatPartner,
            encryptedMessage: encryptedMessage,
            iv: iv,
            messageType: 'audio',
            fileData: {
                name: audioInfo.name,
                size: audioInfo.size,
                type: audioInfo.type,
                duration: audioInfo.duration,
                data: base64Audio
            }
        };
        
        socket.emit('private_message', messageData);
        appendAudioMessage(currentUser, audioInfo, base64Audio, true);
        
    } catch (error) {
        console.error('Error enviando audio:', error);
        appendMessage('Sistema', `Error enviando audio: ${error.message}`, false, true);
    }
}

function appendAudioMessage(sender, audioData, base64Data, isSentByMe) {
    const msgElem = document.createElement('div');
    msgElem.classList.add('message-item', 'audio-message');
    msgElem.classList.add(isSentByMe ? 'sent' : 'received');
    
    const displaySender = sender.includes('@') ? sender.split('@')[0] : sender;
    const duration = audioData.duration || 0;
    const formattedDuration = formatAudioDuration(duration);
    
    const audioId = `audio_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    msgElem.innerHTML = `
        <div class="audio-message-content">
            <div class="audio-icon">🎵</div>
            <div class="audio-info">
                <div class="audio-controls">
                    <button class="audio-play-btn" onclick="toggleAudioPlay('${audioId}', '${base64Data}', '${audioData.type}')">
                        ▶️
                    </button>
                    <div class="audio-progress">
                        <div class="audio-progress-bar" id="progress_${audioId}"></div>
                    </div>
                    <span class="audio-duration">${formattedDuration}</span>
                </div>
                <audio id="${audioId}" preload="metadata" style="display: none;"></audio>
            </div>
        </div>
        <div class="message-sender">${displaySender}</div>
    `;
    
    messagesDiv.appendChild(msgElem);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function formatAudioDuration(seconds) {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
}

window.toggleAudioPlay = function(audioId, base64Data, mimeType) {
    const audioElement = document.getElementById(audioId);
    const playBtn = audioElement.parentElement.querySelector('.audio-play-btn');
    const progressBar = document.getElementById(`progress_${audioId}`);
    
    if (audioElement.paused) {
        if (!audioElement.src) {
            try {
                const byteCharacters = atob(base64Data);
                const byteNumbers = new Array(byteCharacters.length);
                for (let i = 0; i < byteCharacters.length; i++) {
                    byteNumbers[i] = byteCharacters.charCodeAt(i);
                }
                const byteArray = new Uint8Array(byteNumbers);
                const blob = new Blob([byteArray], { type: mimeType });
                const url = URL.createObjectURL(blob);
                audioElement.src = url;
            } catch (error) {
                console.error('Error creando audio:', error);
                return;
            }
        }
        
        audioElement.play();
        playBtn.textContent = '⏸️';
        
        audioElement.ontimeupdate = () => {
            if (audioElement.duration) {
                const progress = (audioElement.currentTime / audioElement.duration) * 100;
                progressBar.style.width = `${progress}%`;
            }
        };
        
        audioElement.onended = () => {
            playBtn.textContent = '▶️';
            progressBar.style.width = '0%';
        };
        
    } else {
        audioElement.pause();
        playBtn.textContent = '▶️';
    }
};

// --- Funciones de archivos mejoradas ---
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        if (file.size > 10 * 1024 * 1024) {
            showToast('El archivo es demasiado grande. Máximo 10MB.', 'error');
            return;
        }
        selectedFile = file;
        document.getElementById('file-name-display').textContent = file.name;
        document.getElementById('file-selected').style.display = 'block';
    }
}

function cancelFileSelection() {
    selectedFile = null;
    document.getElementById('file-input').value = '';
    document.getElementById('file-selected').style.display = 'none';
}

async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    try {
        const response = await fetch('/upload-file', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${authToken}` },
            body: formData
        });
        const result = await response.json();
        if (response.ok) {
            // Mostrar mensaje de escaneo si está disponible
            if (result.scanResult && result.scanResult !== 'Escaneo no disponible') {
                appendMessage('Sistema', `🛡️ Archivo escaneado: ${result.scanResult}`, false, true);
            }
            return result.file;
        } else {
            if (result.threat) {
                appendMessage('Sistema', `⚠️ ARCHIVO RECHAZADO: ${result.message}`, false, true);
                showToast('Archivo detectado como malicioso', 'error');
            }
            throw new Error(result.message);
        }
    } catch (error) {
        console.error('Error subiendo archivo:', error);
        throw error;
    }
}

function appendFileMessage(sender, fileData, isSentByMe) {
    const msgElem = document.createElement('div');
    msgElem.classList.add('message-item', 'file-message');
    msgElem.classList.add(isSentByMe ? 'sent' : 'received');
    const fileIcon = getFileIcon(fileData.type);
    const fileSize = formatFileSize(fileData.size);
    const displaySender = sender.includes('@') ? sender.split('@')[0] : sender;
    
    const downloadData = fileData.data || fileData.file_data || null;
    const downloadDisabled = !downloadData ? 'disabled' : '';
    const downloadClass = !downloadData ? 'download-btn-disabled' : 'download-btn';
    
    msgElem.innerHTML = `
        <div class="file-message-content">
            <div class="file-icon">${fileIcon}</div>
            <div class="file-info">
                <div class="file-name">${fileData.name}</div>
                <div class="file-size">${fileSize}</div>
            </div>
            <button class="${downloadClass}" ${downloadDisabled} onclick="downloadFile('${downloadData}', '${fileData.name}', '${fileData.type}')">
                ${downloadData ? 'Descargar' : 'No disponible'}
            </button>
        </div>
        <div class="message-sender">${displaySender}</div>
    `;
    messagesDiv.appendChild(msgElem);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function getFileIcon(mimeType) {
    if (mimeType.startsWith('image/')) return '🖼️';
    if (mimeType.startsWith('video/')) return '🎥';
    if (mimeType.startsWith('audio/')) return '🎵';
    if (mimeType.includes('pdf')) return '📄';
    if (mimeType.includes('word')) return '📝';
    if (mimeType.includes('excel') || mimeType.includes('spreadsheet')) return '📊';
    return '📎';
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function downloadFile(base64Data, fileName, mimeType) {
    if (!base64Data) {
        showToast('Archivo no disponible para descarga', 'warning');
        return;
    }
    
    try {
        const byteCharacters = atob(base64Data);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray], { type: mimeType });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (error) {
        console.error('Error descargando archivo:', error);
        showToast('Error al descargar el archivo', 'error');
    }
}

// --- UI Functions ---
function showAuthSection() {
    authSection.style.display = 'block';
    chatSection.style.display = 'none';
}

function showChatSection() {
    authSection.style.display = 'none';
    chatSection.style.display = 'block';
}

function displayAuthMessage(message, isError = true) {
    authMessage.textContent = message;
    authMessage.style.color = isError ? '#e06c75' : '#98c379';
}

function appendMessage(sender, message, isSentByMe, isSystem = false) {
    const msgElem = document.createElement('div');
    msgElem.classList.add('message-item');
    if (isSystem) {
        msgElem.classList.add('system');
        msgElem.textContent = message;
    } else {
        msgElem.classList.add(isSentByMe ? 'sent' : 'received');
        const displaySender = sender.includes('@') ? sender.split('@')[0] : sender;
        msgElem.textContent = `${displaySender}: ${message}`;
    }
    messagesDiv.appendChild(msgElem);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function clearMessages() { 
    messagesDiv.innerHTML = ''; 
}

function enableChatInput(enable) {
    messageInput.disabled = !enable;
    sendMessageBtn.disabled = !enable;
    document.getElementById('attach-file-btn').disabled = !enable;
    document.getElementById('record-audio-btn').disabled = !enable;
    document.getElementById('file-input').disabled = !enable;
    if (enable) messageInput.focus();
}

function showChat(friendUsername) {
    currentChatPartner = friendUsername;
    chatPartnerSpan.textContent = friendUsername;
    noChatSelected.style.display = 'none';
    activeChat.style.display = 'flex';
    updateFriendsListUI();

    if (!activeChatKeys[friendUsername]) {
        if (keyExchangeInProgress[friendUsername]) {
            enableChatInput(false);
            return;
        }
        enableChatInput(false);
        clearMessages();
        appendMessage('Sistema', `Estableciendo conexión segura...`, false, true);
        keyExchangeInProgress[friendUsername] = true;
        setTimeout(() => {
            if (socket && socket.connected) requestPublicKey(friendUsername);
            else {
                appendMessage('Sistema', 'Error de conexión. Reconectando...', false, true);
                initializeSocket();
            }
        }, 500);
    } else {
        loadChatHistory(friendUsername);
        enableChatInput(true);
    }
}

function closeChat() {
    if (isRecording) {
        cancelAudioRecording();
    }
    
    const audioElements = document.querySelectorAll('audio');
    audioElements.forEach(audio => {
        audio.pause();
        if (audio.src && audio.src.startsWith('blob:')) {
            URL.revokeObjectURL(audio.src);
        }
    });
    
    if (currentChatPartner) keyExchangeInProgress[currentChatPartner] = false;
    currentChatPartner = null;
    noChatSelected.style.display = 'block';
    activeChat.style.display = 'none';
    clearMessages();
    updateFriendsListUI();
}

function loadChatHistory(friendUsername) {
    clearMessages();
    if (socket && socket.connected && activeChatKeys[friendUsername]) {
        socket.emit('get_chat_history', friendUsername);
    }
}

function requestPublicKey(targetUsername) {
    if (socket && socket.connected) {
        console.log(`Solicitando clave pública de ${targetUsername}`);
        socket.emit('request_public_key', targetUsername);
    } else {
        console.error('Socket no conectado');
        appendMessage('Sistema', 'Error de conexión', false, true);
        keyExchangeInProgress[targetUsername] = false;
    }
}

function renderSearchResults(users) {
    searchResultsDiv.innerHTML = '';
    users.forEach(user => {
        const item = document.createElement('div');
        item.className = 'search-result-item';
        const badge = getUserBadge(user.username, user.role);
        item.innerHTML = `<div><span>${user.username}</span> ${badge}</div><button class="add-friend-btn" onclick="sendFriendRequest('${user.username}')">Agregar</button>`;
        searchResultsDiv.appendChild(item);
    });
}

function sendFriendRequest(targetUsername) { 
    if (socket && socket.connected) socket.emit('send_friend_request', targetUsername); 
}

function renderFriendRequests(requests) {
    friendRequestsList.innerHTML = '';
    requests.forEach(request => {
        const item = document.createElement('div');
        item.className = 'friend-request-item';
        item.innerHTML = `<div class="friend-name">${request.requester_username}</div><div class="friend-actions"><button class="accept-btn" onclick="respondFriendRequest(${request.id}, true)">Aceptar</button><button class="reject-btn" onclick="respondFriendRequest(${request.id}, false)">Rechazar</button></div>`;
        friendRequestsList.appendChild(item);
    });
}

function respondFriendRequest(requestId, accept) { 
    if (socket && socket.connected) socket.emit('respond_friend_request', { requestId, accept }); 
}

function renderFriendsList(friends) {
    friendsData = {};
    friends.forEach(friend => { friendsData[friend.username] = friend; });
    updateFriendsListUI();
}

function updateFriendsListUI() {
    friendsList.innerHTML = '';
    Object.values(friendsData).forEach(friend => {
        const item = document.createElement('div');
        item.className = `friend-item ${friend.isOnline ? 'online' : 'offline'}`;
        if (currentChatPartner === friend.username) item.classList.add('active');
        
        const badge = getUserBadge(friend.username, friend.role);
        const roleIcon = getRoleIcon(friend.role);
        
        item.innerHTML = `
            <div class="friend-info">
                <div class="friend-name">${roleIcon} ${friend.username}</div>
                <div class="friend-status ${friend.isOnline ? 'online' : 'offline'}">${friend.isOnline ? 'En línea' : 'Desconectado'}</div>
            </div>
            <div class="friend-badge-container">${badge}</div>
        `;
        item.addEventListener('click', () => { showChat(friend.username); });
        friendsList.appendChild(item);
    });
}

// --- Funciones para sistema de tickets MEJORADAS ---
async function loadTicketsSection() {
    console.log('Cargando sección de tickets para rol:', currentUserRole);
    
    if (currentUserRole === 'student') {
        await loadTeachers();
        showCreateTicketForm();
    } else if (currentUserRole === 'teacher') {
        showTeacherTicketsDashboard();
    } else if (currentUserRole === 'admin') {
        showAdminTicketsDashboard();
    }
    
    await loadTickets();
    
    // Mostrar la pestaña de tickets si el usuario tiene permisos
    if (currentUserRole === 'student' || currentUserRole === 'teacher' || currentUserRole === 'admin') {
        const ticketsTab = document.querySelector('[onclick="showTab(\'tickets\')"]');
        if (ticketsTab) {
            ticketsTab.style.display = 'block';
        }
    }
}

function showTeacherTicketsDashboard() {
    const ticketsContainer = document.getElementById('tickets-container');
    if (!ticketsContainer) return;
    
    ticketsContainer.innerHTML = `
        <div class="teacher-dashboard">
            <div class="dashboard-header">
                <h3>📋 Panel de Docente - Consultas Recibidas</h3>
                <div class="stats-summary">
                    <div class="stat-box pending">
                        <span class="stat-number" id="pending-count">0</span>
                        <span class="stat-label">Pendientes</span>
                    </div>
                    <div class="stat-box progress">
                        <span class="stat-number" id="progress-count">0</span>
                        <span class="stat-label">En Progreso</span>
                    </div>
                    <div class="stat-box completed">
                        <span class="stat-number" id="completed-count">0</span>
                        <span class="stat-label">Completadas</span>
                    </div>
                </div>
                <div class="availability-controls">
                    <label for="availability-select">Estado:</label>
                    <select id="availability-select" onchange="updateAvailability()">
                        <option value="available">Disponible</option>
                        <option value="busy">Ocupado</option>
                        <option value="offline">No disponible</option>
                    </select>
                </div>
            </div>
            <div class="tickets-filters">
                <button class="filter-btn active" onclick="filterTickets('all')">Todos</button>
                <button class="filter-btn" onclick="filterTickets('abierto')">Pendientes</button>
                <button class="filter-btn" onclick="filterTickets('en-progreso')">En Progreso</button>
                <button class="filter-btn" onclick="filterTickets('cerrado')">Cerrados</button>
            </div>
        </div>
        <div id="tickets-list"></div>
    `;
}

function showAdminTicketsDashboard() {
    const ticketsContainer = document.getElementById('tickets-container');
    if (!ticketsContainer) return;
    
    ticketsContainer.innerHTML = `
        <div class="admin-dashboard">
            <div class="dashboard-header">
                <h3>👑 Panel de Administrador - Sistema de Tickets</h3>
                <div class="admin-stats">
                    <div class="stat-box total">
                        <span class="stat-number" id="total-tickets">0</span>
                        <span class="stat-label">Total Tickets</span>
                    </div>
                    <div class="stat-box active-teachers">
                        <span class="stat-number" id="active-teachers">0</span>
                        <span class="stat-label">Docentes Activos</span>
                    </div>
                </div>
            </div>
            <div class="admin-filters">
                <select id="admin-filter-status" onchange="filterAdminTickets()">
                    <option value="all">Todos los estados</option>
                    <option value="abierto">Abiertos</option>
                    <option value="en-progreso">En progreso</option>
                    <option value="cerrado">Cerrados</option>
                </select>
                <select id="admin-filter-teacher" onchange="filterAdminTickets()">
                    <option value="all">Todos los docentes</option>
                </select>
            </div>
        </div>
        <div id="tickets-list"></div>
    `;
    
    // Cargar lista de docentes para el filtro
    loadTeachersForAdminFilter();
}

async function loadTeachersForAdminFilter() {
    try {
        const response = await fetch('/api/teachers', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const teachers = await response.json();
        
        const select = document.getElementById('admin-filter-teacher');
        if (select) {
            teachers.forEach(teacher => {
                const option = document.createElement('option');
                option.value = teacher.username;
                option.textContent = teacher.username;
                select.appendChild(option);
            });
        }
        
        // Actualizar estadísticas
        document.getElementById('active-teachers').textContent = teachers.length;
    } catch (error) {
        console.error('Error cargando docentes para admin:', error);
    }
}

function filterTickets(status) {
    const buttons = document.querySelectorAll('.filter-btn');
    buttons.forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    const tickets = document.querySelectorAll('.ticket-item');
    tickets.forEach(ticket => {
        if (status === 'all' || ticket.classList.contains(`status-${status}`)) {
            ticket.style.display = 'block';
        } else {
            ticket.style.display = 'none';
        }
    });
}

function filterAdminTickets() {
    const statusFilter = document.getElementById('admin-filter-status').value;
    const teacherFilter = document.getElementById('admin-filter-teacher').value;
    
    const tickets = document.querySelectorAll('.ticket-item');
    tickets.forEach(ticket => {
        let showTicket = true;
        
        if (statusFilter !== 'all' && !ticket.classList.contains(`status-${statusFilter}`)) {
            showTicket = false;
        }
        
        if (teacherFilter !== 'all') {
            const teacherElement = ticket.querySelector('.teacher-name');
            if (!teacherElement || teacherElement.textContent !== teacherFilter) {
                showTicket = false;
            }
        }
        
        ticket.style.display = showTicket ? 'block' : 'none';
    });
}

async function updateAvailability() {
    const availability = document.getElementById('availability-select').value;
    try {
        const response = await fetch('/api/teachers/availability', {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ availability })
        });
        
        if (response.ok) {
            showToast(`Estado actualizado a: ${availability}`, 'success');
        }
    } catch (error) {
        console.error('Error actualizando disponibilidad:', error);
        showToast('Error actualizando estado', 'error');
    }
}

async function loadTeachers() {
    try {
        const response = await fetch('/api/teachers', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const teachers = await response.json();
        
        const select = document.getElementById('teacher-select');
        if (select) {
            select.innerHTML = '<option value="">Selecciona un docente</option>';
            teachers.forEach(teacher => {
                const option = document.createElement('option');
                option.value = teacher.username;
                option.textContent = `${teacher.username} (${teacher.availability})`;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error cargando docentes:', error);
    }
}

function showCreateTicketForm() {
    const ticketsContainer = document.getElementById('tickets-container');
    if (!ticketsContainer) return;
    
    ticketsContainer.innerHTML = `
        <div class="create-ticket-form">
            <h3>📝 Nueva Consulta a Docente</h3>
            <form id="create-ticket-form">
                <select id="teacher-select" required>
                    <option value="">Selecciona un docente</option>
                </select>
                <input type="text" id="ticket-subject" placeholder="Asunto de la consulta" required maxlength="100">
                <textarea id="ticket-question" placeholder="Describe tu consulta detalladamente..." required rows="6" maxlength="500"></textarea>
                <div class="form-footer">
                    <small>Máximo 500 caracteres para la consulta</small>
                    <button type="submit">📤 Enviar Consulta</button>
                </div>
            </form>
        </div>
        <div id="tickets-list"></div>
    `;
    
    document.getElementById('create-ticket-form').addEventListener('submit', createTicket);
}

async function createTicket(event) {
    event.preventDefault();
    
    const teacher_id = document.getElementById('teacher-select').value;
    const subject = document.getElementById('ticket-subject').value;
    const question = document.getElementById('ticket-question').value;
    
    if (!teacher_id || !subject || !question) {
        showToast('Todos los campos son requeridos', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/tickets', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ teacher_id, subject, question })
        });
        
        const result = await response.json();
        if (response.ok) {
            showToast('Consulta enviada exitosamente', 'success');
            document.getElementById('create-ticket-form').reset();
            loadTickets();
        } else {
            showToast(result.message, 'error');
        }
    } catch (error) {
        console.error('Error creando ticket:', error);
        showToast('Error al enviar la consulta', 'error');
    }
}

async function loadTickets() {
    try {
        const response = await fetch('/api/tickets', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const tickets = await response.json();
        
        displayTickets(tickets);
        updateTicketStats(tickets);
    } catch (error) {
        console.error('Error cargando tickets:', error);
    }
}

function updateTicketStats(tickets) {
    if (currentUserRole === 'teacher') {
        const pending = tickets.filter(t => t.status === 'abierto').length;
        const progress = tickets.filter(t => t.status === 'en-progreso').length;
        const completed = tickets.filter(t => t.status === 'cerrado').length;
        
        const pendingElement = document.getElementById('pending-count');
        const progressElement = document.getElementById('progress-count');
        const completedElement = document.getElementById('completed-count');
        
        if (pendingElement) pendingElement.textContent = pending;
        if (progressElement) progressElement.textContent = progress;
        if (completedElement) completedElement.textContent = completed;
    } else if (currentUserRole === 'admin') {
        const totalElement = document.getElementById('total-tickets');
        if (totalElement) totalElement.textContent = tickets.length;
    }
}

function displayTickets(tickets) {
    const ticketsList = document.getElementById('tickets-list');
    if (!ticketsList) return;
    
    if (tickets.length === 0) {
        ticketsList.innerHTML = '<div class="no-tickets"><p>📭 No hay consultas registradas.</p></div>';
        return;
    }
    
    ticketsList.innerHTML = '';
    
    tickets.forEach(ticket => {
        const ticketElement = document.createElement('div');
        ticketElement.className = `ticket-item status-${ticket.status}`;
        
        let actionButtons = '';
        if (currentUserRole === 'teacher' && (ticket.status === 'abierto' || ticket.status === 'en-progreso')) {
            actionButtons = `
                <div class="teacher-actions">
                    ${ticket.status === 'abierto' ? `<button class="btn-take" onclick="updateTicketStatus(${ticket.id}, 'en-progreso')">📝 Tomar consulta</button>` : ''}
                    <textarea id="response-${ticket.id}" placeholder="Escribe tu respuesta aquí..." rows="3" maxlength="500"></textarea>
                    <button class="btn-respond" onclick="respondToTicket(${ticket.id})">✅ Responder y cerrar</button>
                </div>
            `;
        } else if (currentUserRole === 'admin') {
            actionButtons = `
                <div class="admin-actions">
                    <select onchange="updateTicketStatus(${ticket.id}, this.value)">
                        <option value="">Cambiar estado</option>
                        <option value="abierto" ${ticket.status === 'abierto' ? 'selected' : ''}>Abierto</option>
                        <option value="en-progreso" ${ticket.status === 'en-progreso' ? 'selected' : ''}>En progreso</option>
                        <option value="cerrado" ${ticket.status === 'cerrado' ? 'selected' : ''}>Cerrado</option>
                    </select>
                    <button class="btn-delete" onclick="deleteTicket(${ticket.id})">🗑️ Eliminar</button>
                </div>
            `;
        }
        
        ticketElement.innerHTML = `
            <div class="ticket-header">
                <span class="ticket-id">#${ticket.id}</span>
                <span class="ticket-status status-${ticket.status}">${ticket.status.toUpperCase()}</span>
                <span class="ticket-date">${new Date(ticket.created_at).toLocaleDateString('es-PE')}</span>
            </div>
            <div class="ticket-content">
                <h4>${ticket.subject}</h4>
                <div class="ticket-question">
                    <strong>Pregunta:</strong> 
                    <p>${ticket.question}</p>
                </div>
                ${ticket.response ? `
                    <div class="ticket-response">
                        <strong>Respuesta:</strong> 
                        <p>${ticket.response}</p>
                    </div>
                ` : ''}
                ${currentUserRole === 'admin' ? `
                    <div class="ticket-participants">
                        <span class="student-info">👨‍🎓 <span class="student-name">${ticket.student_name}</span></span>
                        <span class="teacher-info">👨‍🏫 <span class="teacher-name">${ticket.teacher_name}</span></span>
                    </div>
                ` : ''}
                ${currentUserRole === 'student' ? `<p><strong>Docente:</strong> ${ticket.teacher_name}</p>` : ''}
                ${currentUserRole === 'teacher' ? `<p><strong>Estudiante:</strong> ${ticket.student_name}</p>` : ''}
            </div>
            <div class="ticket-actions">
                ${actionButtons}
            </div>
        `;
        
        ticketsList.appendChild(ticketElement);
    });
}

async function updateTicketStatus(ticketId, status) {
    try {
        const response = await fetch(`/api/tickets/${ticketId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status })
        });
        
        const result = await response.json();
        if (response.ok) {
            showToast('Ticket actualizado exitosamente', 'success');
            loadTickets();
        } else {
            showToast(result.message, 'error');
        }
    } catch (error) {
        console.error('Error actualizando ticket:', error);
        showToast('Error al actualizar el ticket', 'error');
    }
}

async function respondToTicket(ticketId) {
    const responseText = document.getElementById(`response-${ticketId}`).value;
    if (!responseText || responseText.trim() === '') {
        showToast('Por favor ingresa una respuesta', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`/api/tickets/${ticketId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                status: 'cerrado',
                response: responseText.trim()
            })
        });
        
        const result = await response.json();
        if (response.ok) {
            showToast('Respuesta enviada exitosamente', 'success');
            loadTickets();
        } else {
            showToast(result.message, 'error');
        }
    } catch (error) {
        console.error('Error respondiendo ticket:', error);
        showToast('Error al enviar la respuesta', 'error');
    }
}

async function deleteTicket(ticketId) {
    if (!confirm('¿Estás seguro de que quieres eliminar este ticket? Esta acción no se puede deshacer.')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/tickets/${ticketId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            showToast('Ticket eliminado exitosamente', 'success');
            loadTickets();
        } else {
            showToast('Error al eliminar el ticket', 'error');
        }
    } catch (error) {
        console.error('Error eliminando ticket:', error);
        showToast('Error al eliminar el ticket', 'error');
    }
}

// --- Funciones para sistema de grupos MEJORADAS ---
async function loadGroupsSection() {
    console.log('Cargando sección de grupos');
    await loadMyGroups();
}

async function loadMyGroups() {
    try {
        const response = await fetch('/api/groups', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const groups = await response.json();
        
        displayMyGroups(groups);
    } catch (error) {
        console.error('Error cargando grupos:', error);
        showToast('Error cargando grupos', 'error');
    }
}

function displayMyGroups(groups) {
    const groupsList = document.getElementById('my-groups-list');
    if (!groupsList) return;
    
    if (groups.length === 0) {
        groupsList.innerHTML = `
            <div class="no-groups">
                <p>📭 No tienes grupos aún</p>
                <button class="create-first-group-btn" onclick="showCreateGroupModal()">Crear tu primer grupo</button>
            </div>
        `;
        return;
    }
    
    groupsList.innerHTML = '';
    
    groups.forEach(group => {
        const groupItem = document.createElement('div');
        groupItem.className = 'group-item';
        groupItem.onclick = () => openGroupChat(group);
        
        groupItem.innerHTML = `
            <div class="group-info">
                <h4>${group.name}</h4>
                <p>${group.description || 'Sin descripción'}</p>
                <div class="group-meta">
                    <span>👥 ${group.member_count} miembros</span>
                    <span class="group-role">${group.user_role}</span>
                </div>
            </div>
        `;
        
        groupsList.appendChild(groupItem);
    });
}

function openGroupChat(group) {
    currentGroup = group;
    document.getElementById('current-group-name').textContent = group.name;
    document.getElementById('group-chat-area').style.display = 'flex';
    
    loadGroupMessages(group.id);
}

async function loadGroupMessages(groupId) {
    try {
        const response = await fetch(`/api/groups/${groupId}/messages`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const messages = await response.json();
        
        displayGroupMessages(messages);
    } catch (error) {
        console.error('Error cargando mensajes del grupo:', error);
    }
}

function displayGroupMessages(messages) {
    const messagesContainer = document.getElementById('group-messages');
    if (!messagesContainer) return;
    
    messagesContainer.innerHTML = '';
    
    if (messages.length === 0) {
        messagesContainer.innerHTML = '<div class="no-messages"><p>💬 No hay mensajes aún. ¡Sé el primero en escribir!</p></div>';
        return;
    }
    
    messages.forEach(message => {
        const messageElement = document.createElement('div');
        messageElement.className = `group-message ${message.sender === currentUser ? 'own' : 'other'}`;
        
        messageElement.innerHTML = `
            <div class="message-header">
                <span class="sender">${message.sender}</span>
                <span class="timestamp">${new Date(message.timestamp).toLocaleTimeString()}</span>
            </div>
            <div class="message-content">${message.content}</div>
        `;
        
        messagesContainer.appendChild(messageElement);
    });
    
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

async function createGroup(event) {
    event.preventDefault();
    
    const name = document.getElementById('group-name').value;
    const description = document.getElementById('group-description').value;
    
    if (!name || name.trim() === '') {
        showToast('El nombre del grupo es requerido', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/groups', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                name: name.trim(), 
                description: description.trim() 
            })
        });
        
        const result = await response.json();
        if (response.ok) {
            showToast('Grupo creado exitosamente', 'success');
            closeCreateGroupModal();
            loadMyGroups();
        } else {
            showToast(result.message, 'error');
        }
    } catch (error) {
        console.error('Error creando grupo:', error);
        showToast('Error al crear el grupo', 'error');
    }
}

async function sendGroupMessage() {
    const input = document.getElementById('group-message-input');
    const message = input.value.trim();
    
    if (!message || !currentGroup) return;
    
    try {
        const response = await fetch(`/api/groups/${currentGroup.id}/messages`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ content: message })
        });
        
        if (response.ok) {
            input.value = '';
            loadGroupMessages(currentGroup.id);
        } else {
            showToast('Error enviando mensaje', 'error');
        }
    } catch (error) {
        console.error('Error enviando mensaje:', error);
        showToast('Error enviando mensaje', 'error');
    }
}

// --- Funciones para notificaciones con imágenes ---
async function loadNotificationsSection() {
    console.log('Cargando sección de notificaciones');
    await loadEventNotifications();
    await loadMenuNotifications();
}

async function loadEventNotifications() {
    const eventsContainer = document.getElementById('events-notifications');
    if (!eventsContainer) return;
    
    // Simulamos notificaciones de eventos con imágenes
    const events = [
        {
            id: 1,
            title: 'Hackathon UNI 2024',
            description: 'Participa en el hackathon más grande de la universidad. ¡Premios increíbles!',
            image: '/images/hackathon.jpg',
            date: '2024-07-15',
            category: 'Competencia'
        },
        {
            id: 2,
            title: 'Seminario de Inteligencia Artificial',
            description: 'Conferencia magistral sobre el futuro de la IA en la industria.',
            image: '/images/ai-seminar.jpg',
            date: '2024-07-20',
            category: 'Académico'
        },
        {
            id: 3,
            title: 'Feria de Empleabilidad FIEE',
            description: 'Conecta con las mejores empresas del sector tecnológico.',
            image: '/images/job-fair.jpg',
            date: '2024-07-25',
            category: 'Empleo'
        }
    ];
    
    eventsContainer.innerHTML = '';
    
    events.forEach(event => {
        const eventElement = document.createElement('div');
        eventElement.className = 'notification-item event-notification';
        
        eventElement.innerHTML = `
            <div class="notification-image">
                <img src="${event.image}" alt="${event.title}" onerror="this.src='/images/default-event.jpg'">
            </div>
            <div class="notification-content">
                <div class="notification-category">${event.category}</div>
                <h4>${event.title}</h4>
                <p>${event.description}</p>
                <div class="notification-meta">
                    <span class="notification-date">📅 ${new Date(event.date).toLocaleDateString('es-PE')}</span>
                    <button class="btn-more-info" onclick="showEventDetails(${event.id})">Más información</button>
                </div>
            </div>
        `;
        
        eventsContainer.appendChild(eventElement);
    });
}

async function loadMenuNotifications() {
    const menuContainer = document.getElementById('menu-notifications');
    if (!menuContainer) return;
    
    // Simulamos notificaciones del menú del comedor con imágenes
    const today = new Date();
    const menus = [
        {
            id: 1,
            day: 'Lunes',
            date: today.toISOString().split('T')[0],
            breakfast: 'Desayuno Continental',
            lunch: 'Arroz con Pollo, Ensalada Mixta',
            dinner: 'Sopa de Verduras, Pan Integral',
            image: '/images/menu-monday.jpg',
            price: 'S/. 8.50'
        },
        {
            id: 2,
            day: 'Martes',
            date: new Date(today.getTime() + 24*60*60*1000).toISOString().split('T')[0],
            breakfast: 'Avena con Frutas',
            lunch: 'Lomo Saltado, Arroz Blanco',
            dinner: 'Ensalada César, Jugo Natural',
            image: '/images/menu-tuesday.jpg',
            price: 'S/. 9.00'
        }
    ];
    
    menuContainer.innerHTML = '';
    
    menus.forEach(menu => {
        const menuElement = document.createElement('div');
        menuElement.className = 'notification-item menu-notification';
        
        menuElement.innerHTML = `
            <div class="notification-image">
                <img src="${menu.image}" alt="Menú ${menu.day}" onerror="this.src='/images/default-food.jpg'">
            </div>
            <div class="notification-content">
                <div class="menu-day">${menu.day}</div>
                <h4>Menú del Comedor UNI</h4>
                <div class="menu-details">
                    <div class="meal"><strong>Desayuno:</strong> ${menu.breakfast}</div>
                    <div class="meal"><strong>Almuerzo:</strong> ${menu.lunch}</div>
                    <div class="meal"><strong>Cena:</strong> ${menu.dinner}</div>
                </div>
                <div class="notification-meta">
                    <span class="menu-price">${menu.price}</span>
                    <span class="notification-date">📅 ${new Date(menu.date).toLocaleDateString('es-PE')}</span>
                </div>
            </div>
        `;
        
        menuContainer.appendChild(menuElement);
    });
}

function showEventDetails(eventId) {
    showToast(`Mostrando detalles del evento #${eventId}`, 'info');
    // Aquí se implementaría la lógica para mostrar más detalles del evento
}

function refreshNotifications() {
    showToast('Actualizando notificaciones...', 'info');
    loadEventNotifications();
    loadMenuNotifications();
}

// --- Función mejorada para Google Login ---
function handleGoogleLogin(response) {
    const token = response.credential;
    fetch('/google-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    })
    .then(res => res.json())
    .then(async data => {
        if (data.token) {
            authToken = data.token;
            const payload = JSON.parse(atob(data.token.split('.')[1]));
            currentUser = payload.username;
            currentUserRole = payload.role;
            currentPasswordForKeys = null;
            isGoogleUser = true;
            
            currentUserSpan.textContent = currentUser.split('@')[0];
            displayAuthMessage(data.message, false);

            try {
                let loadedKeyData = await loadKeysFromLocalStorage();
                if (loadedKeyData) {
                    rsaKeyPair = loadedKeyData.rsaKeyPair;
                    activeChatKeys = loadedKeyData.activeChatKeys;
                    console.log("Claves de usuario Google cargadas desde localStorage.");
                } else {
                    console.log("No se encontraron claves para usuario Google. Generando nuevas...");
                    rsaKeyPair = await generateRsaKeyPairInternal();
                    activeChatKeys = {};
                    const publicKeyPem = await exportPublicKeyAsPem(rsaKeyPair.publicKey);
                    await saveKeysToLocalStorage(rsaKeyPair, publicKeyPem, activeChatKeys, null);
                    console.log("Nuevas claves generadas y guardadas para usuario Google.");
                }
            } catch (error) {
                displayAuthMessage("Error manejando claves criptográficas.", true);
                console.error("Error with Google user keys:", error);
                return;
            }

            showChatSection();
            initializeSocket();
            
            // Cargar funcionalidades según el rol
            if (currentUserRole === 'student' || currentUserRole === 'teacher' || currentUserRole === 'admin') {
                loadTicketsSection();
            }
            
            // Actualizar UI para mostrar pestañas disponibles
            updateUIForUserRole(currentUserRole);
        } else {
            displayAuthMessage(data.message || 'Error en autenticación con Google', true);
        }
    })
    .catch(error => {
        displayAuthMessage('Error al autenticarse con Google', true);
        console.error("Google login error:", error);
    });
}

// --- Event Listeners & Socket Logic ---
registerBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const emailPattern = /^[a-zA-Z0-9._%+-]+@uni\.(pe|edu\.pe)$/;
    const passwordPattern = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
    
    if (!username || !password) { 
        displayAuthMessage('Usuario y contraseña requeridos', true); 
        return; 
    }
    if (!emailPattern.test(username)) { 
        displayAuthMessage('Debe usar un correo @uni.pe o @uni.edu.pe', true); 
        return; 
    }
    if (!passwordPattern.test(password)) { 
        displayAuthMessage('La contraseña debe tener al menos 8 caracteres, incluyendo letras, números y especiales.', true); 
        return; 
    }
    
    try {
        const response = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        displayAuthMessage(data.message, !response.ok);
        if (response.ok) {
            showToast('Registro exitoso. Ahora puedes iniciar sesión.', 'success');
        }
    } catch (error) {
        displayAuthMessage('Error al registrarse', true);
    }
});

loginBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    if (!username || !password) { 
        displayAuthMessage('Usuario y contraseña requeridos', true); 
        return; 
    }

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();

        if (response.ok) {
            authToken = data.token;
            currentUser = username;
            currentUserRole = data.user.role;
            currentPasswordForKeys = password;
            isGoogleUser = false;

            currentUserSpan.textContent = currentUser.split('@')[0];
            displayAuthMessage(data.message, false);

            try {
                let loadedKeyData = await loadKeysFromLocalStorage(password);
                if (loadedKeyData) {
                    rsaKeyPair = loadedKeyData.rsaKeyPair;
                    activeChatKeys = loadedKeyData.activeChatKeys;
                    console.log("Cripto-claves cargadas desde localStorage.");
                } else {
                    console.log("No se encontraron claves o no se pudieron descifrar. Generando nuevas claves...");
                    rsaKeyPair = await generateRsaKeyPairInternal();
                    activeChatKeys = {};
                    const publicKeyPem = await exportPublicKeyAsPem(rsaKeyPair.publicKey);
                    await saveKeysToLocalStorage(rsaKeyPair, publicKeyPem, activeChatKeys, password);
                    console.log("Nuevas cripto-claves generadas y guardadas.");
                }
            } catch (keyError) {
                if (keyError.message.includes("Failed to decrypt keys")) {
                    displayAuthMessage("Error al descifrar claves: Contraseña incorrecta o datos corruptos.", true);
                    currentPasswordForKeys = null;
                    return;
                }
                console.error("Error manejando cripto-claves, intentando regenerar:", keyError);
                displayAuthMessage("Error con cripto-claves. Intentando regenerar.", true);
                try {
                    rsaKeyPair = await generateRsaKeyPairInternal();
                    activeChatKeys = {};
                    const publicKeyPem = await exportPublicKeyAsPem(rsaKeyPair.publicKey);
                    await saveKeysToLocalStorage(rsaKeyPair, publicKeyPem, activeChatKeys, password);
                    console.log("Nuevas cripto-claves generadas y guardadas tras error.");
                } catch (regenError) {
                    displayAuthMessage("Fallo crítico al regenerar claves.", true);
                    console.error("Fallo crítico al regenerar claves:", regenError);
                    currentPasswordForKeys = null;
                    return;
                }
            }
            
            showChatSection();
            initializeSocket();
            
            // Cargar funcionalidades según el rol
            if (currentUserRole === 'student' || currentUserRole === 'teacher' || currentUserRole === 'admin') {
                loadTicketsSection();
            }
            
            // Actualizar UI para mostrar pestañas disponibles
            updateUIForUserRole(currentUserRole);

        } else {
            displayAuthMessage(data.message, true);
        }
    } catch (error) {
        displayAuthMessage('Error al iniciar sesión', true);
        console.error("Login error:", error);
    }
});

// Función para actualizar UI según rol
function updateUIForUserRole(role) {
    const ticketsTab = document.querySelector('[onclick="showTab(\'tickets\')"]');
    if (ticketsTab) {
        if (role === 'student' || role === 'teacher' || role === 'admin') {
            ticketsTab.style.display = 'block';
        } else {
            ticketsTab.style.display = 'none';
        }
    }
}

function logout() {
    if (isRecording) {
        cancelAudioRecording();
    }
    
    const audioElements = document.querySelectorAll('audio');
    audioElements.forEach(audio => {
        audio.pause();
        if (audio.src && audio.src.startsWith('blob:')) {
            URL.revokeObjectURL(audio.src);
        }
    });
    
    authToken = null;
    currentUser = null;
    currentUserRole = null;
    currentPasswordForKeys = null;
    isGoogleUser = false;
    rsaKeyPair = null;
    activeChatKeys = {};
    chatHistories = {};
    friendsData = {};
    keyExchangeInProgress = {};
    currentGroup = null;
    
    mediaRecorder = null;
    audioChunks = [];
    isRecording = false;
    recordingStartTime = 0;
    if (recordingTimer) {
        clearInterval(recordingTimer);
        recordingTimer = null;
    }
    
    if (socket) {
        socket.disconnect();
        socket = null;
    }

    clearMessages();
    usernameInput.value = '';
    passwordInput.value = '';
    authMessage.textContent = '';
    
    showAuthSection();
    console.log("Usuario desconectado. Claves y recursos borrados de memoria.");
}

logoutBtn.addEventListener('click', logout);

function initializeSocket() {
    if (socket) { socket.disconnect(); socket = null; }
    connectionRetries = 0;
    connectSocket();
}

function connectSocket() {
    socket = io({
        auth: { token: authToken },
        reconnection: true, 
        reconnectionAttempts: 5, 
        reconnectionDelay: 1000
    });

    socket.on('connect', async () => {
        console.log('Socket conectado');
        connectionRetries = 0;
        
        if (!rsaKeyPair || !rsaKeyPair.publicKey) {
            displayAuthMessage("Error crítico: Claves RSA no disponibles al conectar socket.", true);
            console.error('RSA key pair not available on socket connect.');
            logout();
            return;
        }
        
        try {
            const pem = await exportPublicKeyAsPem(rsaKeyPair.publicKey);
            socket.emit('send_public_key', pem);
        } catch (e) {
            console.error('Error enviando clave pública RSA al servidor:', e);
        }
        
        setTimeout(() => {
            socket.emit('get_friend_requests');
            socket.emit('get_friends_list');
        }, 300);
    });

    socket.on('connect_error', (error) => {
        console.error('Error de conexión socket:', error);
        connectionRetries++;
        if (connectionRetries < MAX_RETRIES) {
            setTimeout(() => { 
                console.log(`Reintentando conexión (${connectionRetries}/${MAX_RETRIES})`); 
                connectSocket(); 
            }, 2000 * connectionRetries);
        } else {
            appendMessage('Sistema', 'Error de conexión persistente. Recarga la página.', false, true);
        }
    });

    socket.on('online_users', (users) => {
        const filteredUsers = users.filter(user => user.username !== currentUser);
        onlineUsersSpan.textContent = `Online: ${filteredUsers.length}`;
        
        // Actualizar estado online de amigos
        Object.keys(friendsData).forEach(friendUsername => {
            const onlineUser = users.find(u => u.username === friendUsername);
            if (onlineUser) {
                friendsData[friendUsername].isOnline = true;
                friendsData[friendUsername].role = onlineUser.role;
            } else {
                friendsData[friendUsername].isOnline = false;
            }
        });
        updateFriendsListUI();
    });

    socket.on('search_results', renderSearchResults);
    
    socket.on('friend_request_sent', (targetUsername) => {
        showToast(`Solicitud enviada a ${targetUsername}`, 'success');
        searchResultsDiv.innerHTML = ''; 
        searchUsersInput.value = '';
    });
    
    socket.on('friend_request_received', (data) => {
        showToast(`${data.requester} te envió solicitud`, 'info');
        socket.emit('get_friend_requests');
    });
    
    socket.on('friend_requests_list', renderFriendRequests);
    
    socket.on('friend_request_accepted', (friendUsername) => {
        showToast(`Ahora eres amigo de ${friendUsername}`, 'success');
        socket.emit('get_friends_list'); 
        socket.emit('get_friend_requests');
    });
    
    socket.on('friend_request_rejected', () => { 
        socket.emit('get_friend_requests'); 
    });
    
    socket.on('friend_request_response', (data) => {
        const message = data.accepted ? `${data.user} aceptó tu solicitud` : `${data.user} rechazó tu solicitud`;
        showToast(message, data.accepted ? 'success' : 'warning');
        if (data.accepted) socket.emit('get_friends_list');
    });
    
    socket.on('friends_list', renderFriendsList);
    
    socket.on('user_offline', (username) => {
        if (friendsData[username]) { 
            friendsData[username].isOnline = false; 
            updateFriendsListUI(); 
        }
    });

    // Eventos para tickets
    socket.on('new_ticket', (data) => {
        if (currentUserRole === 'teacher') {
            showToast(`Nueva consulta de ${data.student}: ${data.subject}`, 'info');
            loadTickets();
        }
    });

    socket.on('ticket_updated', (data) => {
        if (currentUserRole === 'student') {
            showToast(`Tu consulta #${data.ticketId} fue actualizada: ${data.status}`, 'info');
            loadTickets();
        }
    });

    socket.on('receive_public_key', async (data) => {
        const { username, publicKey: friendPublicKeyPem } = data;
        console.log(`Clave pública RSA recibida de ${username}`);
        
        if (username === currentChatPartner) {
            if (!friendPublicKeyPem) {
                appendMessage('Sistema', `Error: Clave pública RSA vacía de ${username}`, false, true);
                keyExchangeInProgress[username] = false; 
                enableChatInput(false); 
                return;
            }
            try {
                const friendPublicKeyRsa = await importPublicKeyFromPem(friendPublicKeyPem);
                const newAesKey = await generateAesKey();
                
                activeChatKeys[username] = newAesKey;
                await saveActiveChatKeysState();

                const wrappedAesKeyBase64 = await wrapAesKey(newAesKey, friendPublicKeyRsa);

                socket.emit('private_message', {
                    receiver: currentChatPartner,
                    encryptedMessage: wrappedAesKeyBase64,
                    iv: 'KEY_EXCHANGE'
                });
                
                appendMessage('Sistema', `Conexión segura establecida con ${username}`, false, true);
                keyExchangeInProgress[username] = false;
                enableChatInput(true);
                setTimeout(() => { loadChatHistory(username); }, 100);
                
            } catch (e) {
                console.error('Error en intercambio de clave AES:', e);
                appendMessage('Sistema', `Error estableciendo chat seguro: ${e.message}`, false, true);
                keyExchangeInProgress[username] = false; 
                enableChatInput(false);
            }
        }
    });

    socket.on('private_message', async (data) => {
        const { sender, encryptedMessage, iv, messageType, fileData } = data;

        if (iv === 'KEY_EXCHANGE') {
            if (friendsData[sender] && rsaKeyPair && rsaKeyPair.privateKey) {
                try {
                    const receivedAesKey = await unwrapAesKey(encryptedMessage, rsaKeyPair.privateKey);
                    activeChatKeys[sender] = receivedAesKey;
                    await saveActiveChatKeysState();
                    keyExchangeInProgress[sender] = false;
                    
                    if (currentChatPartner === sender) {
                        appendMessage('Sistema', `Conexión segura establecida por ${sender}`, false, true);
                        enableChatInput(true);
                        setTimeout(() => { loadChatHistory(sender); }, 100);
                    }
                } catch (e) {
                    console.error('Error descifrando clave AES recibida:', e);
                    keyExchangeInProgress[sender] = false;
                    if (currentChatPartner === sender) {
                        appendMessage('Sistema', `Error en establecimiento de chat seguro con ${sender}`, false, true);
                        enableChatInput(false);
                    }
                }
            }
            return;
        }

        if (friendsData[sender] && activeChatKeys[sender]) {
            try {
                if (messageType === 'audio' && fileData) {
                    const decryptedAudioInfoString = await decryptAes(encryptedMessage, iv, activeChatKeys[sender]);
                    const audioInfo = JSON.parse(decryptedAudioInfoString);
                    const completeAudioData = { ...audioInfo, data: fileData.data };
                    if (currentChatPartner === sender) {
                        appendAudioMessage(sender, completeAudioData, fileData.data, false);
                    }
                } else if (messageType === 'file' && fileData) {
                    const decryptedFileInfoString = await decryptAes(encryptedMessage, iv, activeChatKeys[sender]);
                    const fileInfo = JSON.parse(decryptedFileInfoString);
                    const completeFileData = { ...fileInfo, data: fileData.data };
                    if (currentChatPartner === sender) appendFileMessage(sender, completeFileData, false);
                } else {
                    const decryptedMessage = await decryptAes(encryptedMessage, iv, activeChatKeys[sender]);
                    if (currentChatPartner === sender) appendMessage(sender, decryptedMessage, false);
                }
            } catch (e) {
                console.error('Error descifrando mensaje/archivo/audio:', e);
                if (currentChatPartner === sender) appendMessage(sender, '[ERROR DESCIFRADO]', false);
            }
        } else {
            console.warn(`Mensaje recibido de ${sender} pero no hay clave AES o no es amigo. Se ignora.`);
        }
    });

    socket.on('chat_history', async (messages) => {
        if (!currentChatPartner) return;
        console.log(`Recibido historial de ${messages.length} mensajes para ${currentChatPartner}`);
        
        const systemMessages = Array.from(messagesDiv.querySelectorAll('.system'));
        systemMessages.forEach(msg => {
            if (!msg.textContent.includes('Conexión segura establecida')) msg.remove();
        });
        
        const aesKeyForHistory = activeChatKeys[currentChatPartner];
        if (!aesKeyForHistory) {
            console.warn(`No hay clave AES para descifrar historial de ${currentChatPartner}. Solicitando de nuevo...`);
            if (!keyExchangeInProgress[currentChatPartner]) {
                appendMessage('Sistema', `Clave de chat no encontrada para ${currentChatPartner}. Intentando reestablecer...`, false, true);
                showChat(currentChatPartner);
            }
            return;
        }
        
        for (const msg of messages) {
            if (msg.iv === 'KEY_EXCHANGE') continue;
            try {
                const isSentByMe = msg.sender === currentUser;
                if (msg.message_type === 'audio' && msg.file_data) {
                    const decryptedAudioInfoString = await decryptAes(msg.encryptedMessage, msg.iv, aesKeyForHistory);
                    const audioInfo = JSON.parse(decryptedAudioInfoString);
                    const completeAudioData = {
                        name: msg.file_name || audioInfo.name,
                        size: msg.file_size || audioInfo.size,
                        type: msg.file_type || audioInfo.type,
                        duration: audioInfo.duration || 0,
                        data: msg.file_data
                    };
                    appendAudioMessage(msg.sender, completeAudioData, msg.file_data, isSentByMe);
                } else if (msg.message_type === 'file' && msg.file_data) {
                    const decryptedFileInfoString = await decryptAes(msg.encryptedMessage, msg.iv, aesKeyForHistory);
                    const fileInfo = JSON.parse(decryptedFileInfoString);
                    const completeFileData = {
                        name: msg.file_name || fileInfo.name,
                        size: msg.file_size || fileInfo.size,
                        type: msg.file_type || fileInfo.type,
                        data: msg.file_data
                    };
                    appendFileMessage(msg.sender, completeFileData, isSentByMe);
                } else {
                    const decryptedMessage = await decryptAes(msg.encryptedMessage, msg.iv, aesKeyForHistory);
                    appendMessage(msg.sender, decryptedMessage, isSentByMe);
                }
            } catch (e) {
                console.error('Error descifrando mensaje del historial:', e, msg);
                appendMessage(msg.sender, '[ERROR DESCIFRADO EN HISTORIAL]', msg.sender === currentUser);
            }
        }
    });

    socket.on('error_message', (message) => {
        console.error('Error del servidor:', message);
        appendMessage('Sistema', `Error: ${message}`, false, true);
    });

    socket.on('disconnect', (reason) => {
        console.log('Socket desconectado:', reason);
        Object.keys(keyExchangeInProgress).forEach(user => { keyExchangeInProgress[user] = false; });
        if (currentChatPartner) enableChatInput(false);
        if (reason === 'io server disconnect' && authToken) {
            setTimeout(() => { if (authToken) connectSocket(); }, 2000);
        }
    });

    socket.on('reconnect', () => {
        console.log('Socket reconectado');
        if (rsaKeyPair && rsaKeyPair.publicKey && socket.connected) {
            exportPublicKeyAsPem(rsaKeyPair.publicKey)
                .then(pem => socket.emit('send_public_key', pem))
                .catch(e => console.error("Error reenviando clave pública en reconexión", e));
        }

        if (currentChatPartner) {
            if (activeChatKeys[currentChatPartner]) {
                loadChatHistory(currentChatPartner);
            } else {
                showChat(currentChatPartner);
            }
        }
    });
}

// --- Event Listeners principales ---
searchUsersInput.addEventListener('input', (e) => {
    const searchTerm = e.target.value.trim();
    if (searchTerm.length >= 2) { 
        if (socket && socket.connected) socket.emit('search_users', searchTerm); 
    } else { 
        searchResultsDiv.innerHTML = ''; 
    }
});

sendMessageBtn.addEventListener('click', async () => {
    const message = messageInput.value.trim();
    if ((!message && !selectedFile) || !currentChatPartner) return;

    if (!activeChatKeys[currentChatPartner]) {
        appendMessage('Sistema', `Conexión segura con ${currentChatPartner} no establecida. Intentando...`, false, true);
        if (!keyExchangeInProgress[currentChatPartner]) {
            showChat(currentChatPartner);
        }
        return;
    }
    
    try {
        let messageData = {};
        if (selectedFile) {
            appendMessage('Sistema', 'Subiendo archivo...', false, true);
            const uploadedFileData = await uploadFile(selectedFile);
            
            const fileInfoToEncrypt = JSON.stringify({
                name: uploadedFileData.name,
                size: uploadedFileData.size,
                type: uploadedFileData.type,
            });
            const { encryptedMessage, iv } = await encryptAes(fileInfoToEncrypt, activeChatKeys[currentChatPartner]);
            
            messageData = {
                receiver: currentChatPartner,
                encryptedMessage: encryptedMessage,
                iv: iv,
                messageType: 'file',
                fileData: {
                    name: uploadedFileData.name,
                    size: uploadedFileData.size,
                    type: uploadedFileData.type,
                    data: uploadedFileData.data
                }
            };
            socket.emit('private_message', messageData);
            appendFileMessage(currentUser, uploadedFileData, true);
            cancelFileSelection();
            
        } else if (message) {
            const { encryptedMessage, iv } = await encryptAes(message, activeChatKeys[currentChatPartner]);
            messageData = {
                receiver: currentChatPartner,
                encryptedMessage: encryptedMessage,
                iv: iv,
                messageType: 'text'
            };
            socket.emit('private_message', messageData);
            appendMessage(currentUser, message, true);
        }
        messageInput.value = '';
    } catch (e) {
        appendMessage('Sistema', `Error enviando: ${e.message}`, false, true);
        console.error("Error sending message:", e);
    }
});

clearChatBtn.addEventListener('click', clearMessages);
closeChatBtn.addEventListener('click', closeChat);

// --- Funciones globales ---
window.handleFileSelect = handleFileSelect;
window.cancelFileSelection = cancelFileSelection;
window.downloadFile = downloadFile;
window.sendFriendRequest = sendFriendRequest;
window.respondFriendRequest = respondFriendRequest;
window.handleGoogleLogin = handleGoogleLogin;
window.startAudioRecording = startAudioRecording;
window.stopAudioRecording = stopAudioRecording;
window.cancelAudioRecording = cancelAudioRecording;
window.updateTicketStatus = updateTicketStatus;
window.respondToTicket = respondToTicket;
window.deleteTicket = deleteTicket;
window.updateAvailability = updateAvailability;
window.filterTickets = filterTickets;
window.filterAdminTickets = filterAdminTickets;
window.showEventDetails = showEventDetails;
window.refreshNotifications = refreshNotifications;
window.openGroupChat = openGroupChat;
window.createGroup = createGroup;
window.sendGroupMessage = sendGroupMessage;
window.loadGroupsSection = loadGroupsSection;
window.loadNotificationsSection = loadNotificationsSection;

// --- Toast System ---
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container') || createToastContainer();
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const toastId = 'toast_' + Date.now();
    toast.id = toastId;
    
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    toast.innerHTML = `
        <div class="toast-content">
            <span class="toast-icon">${icons[type] || icons.info}</span>
            <span class="toast-message">${message}</span>
            <button class="toast-close" onclick="removeToast('${toastId}')">×</button>
        </div>
        <div class="toast-progress"></div>
    `;
    
    container.appendChild(toast);
    
    // Auto-remover después de 5 segundos
    setTimeout(() => {
        removeToast(toastId);
    }, 5000);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
    return container;
}

function removeToast(toastId) {
    const toast = document.getElementById(toastId);
    if (toast && toast.parentElement) {
        toast.classList.add('toast-removing');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 300);
    }
}

window.removeToast = removeToast;
window.showToast = showToast;

// --- Funciones específicas de la aplicación ---

// Función para invitar usuarios a grupos
window.inviteUserToGroup = async function(username) {
    if (!currentGroup) {
        showToast('No hay grupo seleccionado', 'error');
        return;
    }
    
    try {
        const response = await fetch(`/api/groups/${currentGroup.id}/invite`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });
        
        const result = await response.json();
        if (response.ok) {
            showToast(`Invitación enviada a ${username}`, 'success');
        } else {
            showToast(result.message, 'error');
        }
    } catch (error) {
        console.error('Error invitando usuario:', error);
        showToast('Error enviando invitación', 'error');
    }
};

// Función para salir del grupo actual
window.leaveCurrentGroup = async function() {
    if (!currentGroup) {
        showToast('No hay grupo seleccionado', 'error');
        return;
    }
    
    try {
        const response = await fetch(`/api/groups/${currentGroup.id}/leave`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const result = await response.json();
        if (response.ok) {
            showToast('Has salido del grupo', 'success');
            closeGroupChat();
            loadMyGroups();
        } else {
            showToast(result.message, 'error');
        }
    } catch (error) {
        console.error('Error saliendo del grupo:', error);
        showToast('Error al salir del grupo', 'error');
    }
};

// Función para refrescar notificaciones
window.refreshNotifications = function() {
    showToast('Actualizando notificaciones...', 'info');
    if (document.getElementById('notifications-tab').classList.contains('active')) {
        loadNotificationsSection();
    }
};

// Función para marcar notificaciones como leídas
window.markAllAsRead = function() {
    // Aquí se implementaría la lógica para marcar como leídas
    showToast('Notificaciones marcadas como leídas', 'success');
    
    // Remover indicadores visuales de no leído
    const unreadItems = document.querySelectorAll('.notification-item.unread');
    unreadItems.forEach(item => {
        item.classList.remove('unread');
    });
};

// --- Inicialización del DOM ---
document.addEventListener('DOMContentLoaded', function() {
    const recordBtn = document.getElementById('record-audio-btn');
    const recordingIndicator = document.getElementById('recording-indicator');
    
    if (!recordBtn || !recordingIndicator) {
        console.warn('Elementos de grabación de audio no encontrados. Asegúrate de actualizar el HTML.');
    }
    
    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (!sendMessageBtn.disabled) {
                    sendMessageBtn.click();
                }
            }
        });
    }
    
    // Event listener para enviar mensajes de grupo
    const groupMessageInput = document.getElementById('group-message-input');
    const sendGroupMessageBtn = document.getElementById('send-group-message-btn');
    
    if (groupMessageInput && sendGroupMessageBtn) {
        groupMessageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendGroupMessage();
            }
        });
        
        sendGroupMessageBtn.addEventListener('click', sendGroupMessage);
    }
    
    // Event listener para crear grupos
    const createGroupForm = document.getElementById('create-group-form');
    if (createGroupForm) {
        createGroupForm.addEventListener('submit', createGroup);
    }
    
    // Inicialización de componentes
    console.log('🚀 Client.js inicializado completamente');
});

// --- Variables y funciones del Temporizador Pomodoro (mantenidas) ---
let pomodoroTimer = null;
let pomodoroTimeLeft = 0;
let pomodoroCurrentMode = 'work';
let pomodoroSessionCount = 0;
let pomodoroIsRunning = false;
let pomodoroIsPaused = false;
let pomodoroTotalTime = 0;

let pomodoroConfig = {
    workTime: 25,
    breakTime: 5,
    longBreakTime: 15,
    sessionsUntilLong: 4
};

let pomodoroStats = {
    sessionsToday: 0,
    totalSessions: 0,
    studyTimeToday: 0
};

let pomodoroAudio = null;

function initializePomodoro() {
    loadPomodoroStats();
    loadPomodoroConfig();
    updatePomodoroDisplay();
    updatePomodoroStats();
    
    try {
        pomodoroAudio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmMfAQec0/LNeyYEJHfE8N2QQAoUXrTp66hVFApGn+DyvmMfAQec0/LNeyYEJHfE8N2QQAoUXrTp66hVFApGn+DyvmMfAQec0/LNeyYEJHfE8N2QQAoUXrTp66hVFApGn+DyvmMfAQec0/LNeyYEJHfE8N2QQAoUXrTp66hVFApGn+DyvmMfAQec0/LNeyYEJHfE8N2QQAoUXrTp66hVFApGn+DyvmMfAQec0/LNeyYEJHfE8N2QQAoUXrTp66hVFApGn+DyvmMfAQec0/LNeyYEJHfE8N2QQAoUXrTp66hVFApGn+DyvmMfAQec0/LNeyYEJHfE8N2QQAoUXrTp66hVFApGn+DyvmMfAQec0/LNeyYE');
    } catch (e) {
        console.log('Audio notification not available');
    }
}

function loadPomodoroConfig() {
    const stored = localStorage.getItem('pomodoro-config');
    if (stored) {
        pomodoroConfig = { ...pomodoroConfig, ...JSON.parse(stored) };
        if (document.getElementById('work-time')) {
            document.getElementById('work-time').value = pomodoroConfig.workTime;
            document.getElementById('break-time').value = pomodoroConfig.breakTime;
            document.getElementById('long-break-time').value = pomodoroConfig.longBreakTime;
            document.getElementById('sessions-until-long').value = pomodoroConfig.sessionsUntilLong;
        }
    }
}

function savePomodoroConfig() {
    if (document.getElementById('work-time')) {
        pomodoroConfig.workTime = parseInt(document.getElementById('work-time').value) || 25;
        pomodoroConfig.breakTime = parseInt(document.getElementById('break-time').value) || 5;
        pomodoroConfig.longBreakTime = parseInt(document.getElementById('long-break-time').value) || 15;
        pomodoroConfig.sessionsUntilLong = parseInt(document.getElementById('sessions-until-long').value) || 4;
        
        localStorage.setItem('pomodoro-config', JSON.stringify(pomodoroConfig));
    }
}

function loadPomodoroStats() {
    const stored = localStorage.getItem('pomodoro-stats');
    const today = new Date().toDateString();
    const lastDate = localStorage.getItem('pomodoro-last-date');
    
    if (stored) {
        pomodoroStats = { ...pomodoroStats, ...JSON.parse(stored) };
    }
    
    if (lastDate !== today) {
        pomodoroStats.sessionsToday = 0;
        pomodoroStats.studyTimeToday = 0;
        localStorage.setItem('pomodoro-last-date', today);
        savePomodoroStats();
    }
}

function savePomodoroStats() {
    localStorage.setItem('pomodoro-stats', JSON.stringify(pomodoroStats));
}

function updatePomodoroStats() {
    if (document.getElementById('sessions-today')) {
        document.getElementById('sessions-today').textContent = pomodoroStats.sessionsToday;
        document.getElementById('total-sessions').textContent = pomodoroStats.totalSessions;
        
        const hours = Math.floor(pomodoroStats.studyTimeToday / 60);
        const minutes = pomodoroStats.studyTimeToday % 60;
        document.getElementById('study-time-today').textContent = hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
    }
}

function startPomodoroTimer() {
    if (pomodoroIsPaused) {
        pomodoroIsPaused = false;
    } else {
        savePomodoroConfig();
        const timeInMinutes = pomodoroCurrentMode === 'work' ? pomodoroConfig.workTime :
                            pomodoroCurrentMode === 'break' ? pomodoroConfig.breakTime :
                            pomodoroConfig.longBreakTime;
        pomodoroTimeLeft = timeInMinutes * 60;
        pomodoroTotalTime = pomodoroTimeLeft;
    }
    
    pomodoroIsRunning = true;
    
    if (document.getElementById('start-btn')) {
        document.getElementById('start-btn').disabled = true;
        document.getElementById('pause-btn').disabled = false;
        document.getElementById('stop-btn').disabled = false;
        document.getElementById('pomodoro-status').textContent = 'En progreso...';
        
        document.getElementById('pomodoro-timer').classList.add('running');
        const timerDisplay = document.getElementById('timer-display');
        if (timerDisplay) timerDisplay.classList.add('pulsing');
    }
    
    pomodoroTimer = setInterval(updatePomodoroTimer, 1000);
    playPomodoroSound();
}

function pausePomodoroTimer() {
    pomodoroIsRunning = false;
    pomodoroIsPaused = true;
    
    clearInterval(pomodoroTimer);
    
    if (document.getElementById('start-btn')) {
        document.getElementById('start-btn').disabled = false;
        document.getElementById('pause-btn').disabled = true;
        document.getElementById('pomodoro-status').textContent = 'Pausado';
        
        document.getElementById('pomodoro-timer').classList.remove('running');
        const timerDisplay = document.getElementById('timer-display');
        if (timerDisplay) timerDisplay.classList.remove('pulsing');
    }
}

function stopPomodoroTimer() {
    pomodoroIsRunning = false;
    pomodoroIsPaused = false;
    
    clearInterval(pomodoroTimer);
    
    const timeInMinutes = pomodoroCurrentMode === 'work' ? pomodoroConfig.workTime :
                        pomodoroCurrentMode === 'break' ? pomodoroConfig.breakTime :
                        pomodoroConfig.longBreakTime;
    pomodoroTimeLeft = timeInMinutes * 60;
    pomodoroTotalTime = pomodoroTimeLeft;
    
    if (document.getElementById('start-btn')) {
        document.getElementById('start-btn').disabled = false;
        document.getElementById('pause-btn').disabled = true;
        document.getElementById('stop-btn').disabled = true;
        document.getElementById('pomodoro-status').textContent = 'Detenido';
        
        document.getElementById('pomodoro-timer').classList.remove('running');
        const timerDisplay = document.getElementById('timer-display');
        if (timerDisplay) timerDisplay.classList.remove('pulsing');
    }
    
    updatePomodoroDisplay();
    updateProgressBar();
}

function skipPomodoroSession() {
    if (pomodoroIsRunning) {
        clearInterval(pomodoroTimer);
    }
    completePomodoroSession();
}

function updatePomodoroTimer() {
    pomodoroTimeLeft--;
    
    updatePomodoroDisplay();
    updateProgressBar();
    
    if (pomodoroTimeLeft <= 0) {
        clearInterval(pomodoroTimer);
        completePomodoroSession();
    }
}

function completePomodoroSession() {
    pomodoroIsRunning = false;
    pomodoroIsPaused = false;
    
    if (pomodoroCurrentMode === 'work') {
        pomodoroSessionCount++;
        pomodoroStats.sessionsToday++;
        pomodoroStats.totalSessions++;
        pomodoroStats.studyTimeToday += pomodoroConfig.workTime;
        savePomodoroStats();
    }
    
    let nextMode = 'work';
    let notificationMessage = '';
    
    if (pomodoroCurrentMode === 'work') {
        if (pomodoroSessionCount % pomodoroConfig.sessionsUntilLong === 0) {
            nextMode = 'longBreak';
            notificationMessage = '¡Excelente trabajo! Es hora de un descanso largo 😎';
        } else {
            nextMode = 'break';
            notificationMessage = '¡Buen trabajo! Es hora de un descanso corto ☕';
        }
    } else {
        nextMode = 'work';
        notificationMessage = '¡Descanso terminado! Hora de volver al trabajo 💪';
    }
    
    pomodoroCurrentMode = nextMode;
    
    const timeInMinutes = pomodoroCurrentMode === 'work' ? pomodoroConfig.workTime :
                        pomodoroCurrentMode === 'break' ? pomodoroConfig.breakTime :
                        pomodoroConfig.longBreakTime;
    pomodoroTimeLeft = timeInMinutes * 60;
    pomodoroTotalTime = pomodoroTimeLeft;
    
    updatePomodoroModeUI();
    updatePomodoroDisplay();
    updatePomodoroStats();
    updateProgressBar();
    
    if (document.getElementById('start-btn')) {
        document.getElementById('start-btn').disabled = false;
        document.getElementById('pause-btn').disabled = true;
        document.getElementById('stop-btn').disabled = true;
        document.getElementById('pomodoro-status').textContent = 'Sesión completada';
        
        document.getElementById('pomodoro-timer').classList.remove('running');
        const timerDisplay = document.getElementById('timer-display');
        if (timerDisplay) timerDisplay.classList.remove('pulsing');
    }
    
    showPomodoroNotification(notificationMessage);
    playPomodoroCompletionSound();
    showToast(notificationMessage, 'success');
}

function updatePomodoroDisplay() {
    const minutes = Math.floor(pomodoroTimeLeft / 60);
    const seconds = pomodoroTimeLeft % 60;
    const timeString = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    
    const timerDisplay = document.getElementById('timer-display');
    if (timerDisplay) {
        timerDisplay.textContent = timeString;
    }
    
    if (pomodoroIsRunning) {
        document.title = `${timeString} - ${pomodoroCurrentMode === 'work' ? '📚' : '☕'} UNISECURITY`;
    } else {
        document.title = 'UNISECURITY';
    }
}

function updatePomodoroModeUI() {
    const container = document.getElementById('pomodoro-timer');
    const modeElement = document.getElementById('timer-mode');
    const sessionElement = document.getElementById('timer-session');
    
    if (!container) return;
    
    container.classList.remove('work-mode', 'break-mode', 'long-break-mode');
    
    switch (pomodoroCurrentMode) {
        case 'work':
            container.classList.add('work-mode');
            if (modeElement) modeElement.textContent = '📚 Sesión de Estudio';
            if (sessionElement) sessionElement.textContent = `Sesión ${(pomodoroSessionCount % pomodoroConfig.sessionsUntilLong) + 1} de ${pomodoroConfig.sessionsUntilLong}`;
            break;
        case 'break':
            container.classList.add('break-mode');
            if (modeElement) modeElement.textContent = '☕ Descanso Corto';
            if (sessionElement) sessionElement.textContent = 'Relájate un momento';
            break;
        case 'longBreak':
            container.classList.add('long-break-mode');
            if (modeElement) modeElement.textContent = '🏖️ Descanso Largo';
            if (sessionElement) sessionElement.textContent = 'Tiempo para recargar energías';
            break;
    }
}

function updateProgressBar() {
    const progressFill = document.getElementById('progress-fill');
    if (progressFill && pomodoroTotalTime > 0) {
        const progress = ((pomodoroTotalTime - pomodoroTimeLeft) / pomodoroTotalTime) * 100;
        progressFill.style.width = `${progress}%`;
    }
}

function showPomodoroNotification(message) {
    const notification = document.getElementById('timer-notification');
    const messageElement = document.getElementById('notification-message');
    
    if (notification && messageElement) {
        messageElement.textContent = message;
        notification.classList.add('show');
        
        setTimeout(() => {
            notification.classList.remove('show');
        }, 4000);
    }
    
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('🍅 Pomodoro Timer', {
            body: message,
            icon: 'uni.png'
        });
    }
}

function playPomodoroSound() {
    if (pomodoroAudio) {
        pomodoroAudio.currentTime = 0;
        pomodoroAudio.play().catch(e => console.log('Audio play failed:', e));
    }
}

function playPomodoroCompletionSound() {
    if (pomodoroAudio) {
        let count = 0;
        const playInterval = setInterval(() => {
            pomodoroAudio.currentTime = 0;
            pomodoroAudio.play().catch(e => console.log('Audio play failed:', e));
            count++;
            if (count >= 3) {
                clearInterval(playInterval);
            }
        }, 500);
    }
}

function togglePomodoroCollapse() {
    const container = document.getElementById('pomodoro-timer');
    const content = document.getElementById('pomodoro-content');
    const toggleBtn = document.getElementById('pomodoro-toggle-btn');
    
    if (!container || !content || !toggleBtn) return;
    
    if (content.classList.contains('hidden')) {
        content.classList.remove('hidden');
        container.classList.remove('collapsed');
        toggleBtn.textContent = 'Minimizar';
    } else {
        content.classList.add('hidden');
        container.classList.add('collapsed');
        toggleBtn.textContent = 'Expandir';
    }
}

function setupPomodoroEventListeners() {
    const configInputs = ['work-time', 'break-time', 'long-break-time', 'sessions-until-long'];
    configInputs.forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener('change', savePomodoroConfig);
            input.addEventListener('blur', savePomodoroConfig);
        }
    });
    
    if ('Notification' in window && Notification.permission === 'default') {
        setTimeout(() => {
            Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                    console.log('Notification permission granted');
                }
            });
        }, 2000);
    }
}

// Funciones globales del Pomodoro
window.startPomodoroTimer = startPomodoroTimer;
window.pausePomodoroTimer = pausePomodoroTimer;
window.stopPomodoroTimer = stopPomodoroTimer;
window.skipPomodoroSession = skipPomodoroSession;
window.togglePomodoroCollapse = togglePomodoroCollapse;

// Inicialización final
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('pomodoro-timer')) {
        initializePomodoro();
        setupPomodoroEventListeners();
        updatePomodoroModeUI();
    }
});

window.addEventListener('beforeunload', function() {
    if (pomodoroTimer) {
        clearInterval(pomodoroTimer);
    }
});

document.addEventListener('visibilitychange', function() {
    if (document.hidden && pomodoroIsRunning) {
        console.log('Page hidden, timer continues in background');
    } else if (!document.hidden && pomodoroIsRunning) {
        console.log('Page visible, timer continues');
    }
});

document.addEventListener('keydown', function(e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
        return;
    }
    
    if (e.ctrlKey && e.shiftKey && e.key === 'S') {
        e.preventDefault();
        if (pomodoroIsRunning) {
            pausePomodoroTimer();
        } else {
            startPomodoroTimer();
        }
    }
    
    if (e.ctrlKey && e.shiftKey && e.key === 'D') {
        e.preventDefault();
        stopPomodoroTimer();
    }
    
    if (e.ctrlKey && e.shiftKey && e.key === 'N') {
        e.preventDefault();
        skipPomodoroSession();
    }
});

console.log('🚀 UNISECURITY Client.js loaded successfully!');
console.log('🍅 Pomodoro Timer loaded successfully!');
console.log('⚙️ Todas las funciones cargadas correctamente!');
console.log('Shortcuts: Ctrl+Shift+S (Start/Pause), Ctrl+Shift+D (Stop), Ctrl+Shift+N (Skip)');