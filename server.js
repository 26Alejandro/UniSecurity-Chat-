const express = require('express');
const https = require('https');
const fs = require('fs');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios'); // Para VirusTotal API

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '1024943540370-jr5tfre3d4em533pof6dmm03n0etgp7f.apps.googleusercontent.com';
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || 'a2c0da2d97ca08199c753f629ca8acd4b91b64e07413b80ff426d708bb6840b4';

// Google OAuth Client
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Configuración HTTPS
const httpsOptions = {
    key: fs.readFileSync('./key.pem'),
    cert: fs.readFileSync('./cert.pem')
};

const server = https.createServer(httpsOptions, app);
const io = new Server(server);

// Base de datos SQLite
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error al abrir la base de datos', err.message);
    } else {
        console.log('Conectado a la base de datos SQLite.');
        initializeTables();
    }
});

// Función para inicializar todas las tablas
function initializeTables() {
    // Tabla de usuarios (modificada para incluir googleId y role)
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        googleId TEXT UNIQUE,
        publicKey TEXT,
        role TEXT DEFAULT 'student',
        availability TEXT DEFAULT 'available',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'users':", err.message);
        } else {
            console.log("Tabla 'users' verificada/creada.");
            
            // Agregar columnas faltantes
            const columnsToAdd = [
                { name: 'googleId', type: 'TEXT' },
                { name: 'role', type: 'TEXT DEFAULT "student"' },
                { name: 'availability', type: 'TEXT DEFAULT "available"' }
            ];
            
            columnsToAdd.forEach(column => {
                db.run(`ALTER TABLE users ADD COLUMN ${column.name} ${column.type}`, (err) => {
                    if (err && !err.message.includes('duplicate column name')) {
                        console.error(`Error al agregar columna '${column.name}':`, err.message);
                    }
                });
            });

            // Crear cuenta de administrador si no existe
            createAdminAccount();
            // Actualizar roles basados en email
            updateUserRoles();
        }
    });

    // Tabla de solicitudes de amistad
    db.run(`CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        requester_username TEXT,
        receiver_username TEXT,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (requester_username) REFERENCES users (username),
        FOREIGN KEY (receiver_username) REFERENCES users (username),
        UNIQUE(requester_username, receiver_username)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'friend_requests':", err.message);
        } else {
            console.log("Tabla 'friend_requests' verificada/creada.");
        }
    });

    // Tabla de amistades confirmadas
    db.run(`CREATE TABLE IF NOT EXISTS friendships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_username TEXT,
        user2_username TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user1_username) REFERENCES users (username),
        FOREIGN KEY (user2_username) REFERENCES users (username),
        UNIQUE(user1_username, user2_username)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'friendships':", err.message);
        } else {
            console.log("Tabla 'friendships' verificada/creada.");
        }
    });

    // Tabla de mensajes mejorada
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id TEXT,
        sender TEXT,
        receiver TEXT,
        encryptedMessage TEXT,
        iv TEXT,
        message_type TEXT DEFAULT 'text',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        file_name TEXT,
        file_size INTEGER,
        file_type TEXT,
        file_data TEXT
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'messages':", err.message);
        } else {
            console.log("Tabla 'messages' verificada/creada.");
            
            // Verificar y agregar columnas faltantes para archivos si no existen
            const columnsToAdd = [
                { name: 'message_type', type: 'TEXT DEFAULT "text"' },
                { name: 'file_name', type: 'TEXT' },
                { name: 'file_size', type: 'INTEGER' },
                { name: 'file_type', type: 'TEXT' },
                { name: 'file_data', type: 'TEXT' }
            ];
            
            columnsToAdd.forEach(column => {
                db.run(`ALTER TABLE messages ADD COLUMN ${column.name} ${column.type}`, (err) => {
                    if (err && !err.message.includes('duplicate column name')) {
                        console.error(`Error al agregar columna '${column.name}':`, err.message);
                    }
                });
            });
        }
    });

    // Nueva tabla: Tickets para consultas a docentes (MEJORADA)
    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT,
        teacher_id TEXT,
        subject TEXT,
        question TEXT,
        status TEXT DEFAULT 'abierto',
        response TEXT,
        priority TEXT DEFAULT 'normal',
        category TEXT DEFAULT 'general',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES users (username),
        FOREIGN KEY (teacher_id) REFERENCES users (username)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'tickets':", err.message);
        } else {
            console.log("Tabla 'tickets' verificada/creada.");
            
            // Agregar columnas nuevas
            const columnsToAdd = [
                { name: 'priority', type: 'TEXT DEFAULT "normal"' },
                { name: 'category', type: 'TEXT DEFAULT "general"' }
            ];
            
            columnsToAdd.forEach(column => {
                db.run(`ALTER TABLE tickets ADD COLUMN ${column.name} ${column.type}`, (err) => {
                    if (err && !err.message.includes('duplicate column name')) {
                        console.error(`Error al agregar columna '${column.name}':`, err.message);
                    }
                });
            });
        }
    });

    // Nueva tabla: Grupos (MEJORADA)
    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        created_by TEXT,
        max_members INTEGER DEFAULT 50,
        is_private BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (username)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'groups':", err.message);
        } else {
            console.log("Tabla 'groups' verificada/creada.");
            
            // Agregar columnas nuevas
            const columnsToAdd = [
                { name: 'max_members', type: 'INTEGER DEFAULT 50' },
                { name: 'is_private', type: 'BOOLEAN DEFAULT 0' }
            ];
            
            columnsToAdd.forEach(column => {
                db.run(`ALTER TABLE groups ADD COLUMN ${column.name} ${column.type}`, (err) => {
                    if (err && !err.message.includes('duplicate column name')) {
                        console.error(`Error al agregar columna '${column.name}':`, err.message);
                    }
                });
            });
        }
    });

    // Nueva tabla: Miembros de grupos
    db.run(`CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        user_id TEXT,
        role TEXT DEFAULT 'member',
        joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups (id),
        FOREIGN KEY (user_id) REFERENCES users (username),
        UNIQUE(group_id, user_id)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'group_members':", err.message);
        } else {
            console.log("Tabla 'group_members' verificada/creada.");
        }
    });

    // Nueva tabla: Encuestas
    db.run(`CREATE TABLE IF NOT EXISTS polls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        question TEXT NOT NULL,
        created_by TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (group_id) REFERENCES groups (id),
        FOREIGN KEY (created_by) REFERENCES users (username)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'polls':", err.message);
        } else {
            console.log("Tabla 'polls' verificada/creada.");
        }
    });

    // Nueva tabla: Opciones de encuestas
    db.run(`CREATE TABLE IF NOT EXISTS poll_options (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poll_id INTEGER,
        option_text TEXT NOT NULL,
        votes INTEGER DEFAULT 0,
        FOREIGN KEY (poll_id) REFERENCES polls (id)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'poll_options':", err.message);
        } else {
            console.log("Tabla 'poll_options' verificada/creada.");
        }
    });

    // Nueva tabla: Votos de usuarios
    db.run(`CREATE TABLE IF NOT EXISTS user_votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poll_id INTEGER,
        user_id TEXT,
        option_id INTEGER,
        voted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (poll_id) REFERENCES polls (id),
        FOREIGN KEY (user_id) REFERENCES users (username),
        FOREIGN KEY (option_id) REFERENCES poll_options (id),
        UNIQUE(poll_id, user_id)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'user_votes':", err.message);
        } else {
            console.log("Tabla 'user_votes' verificada/creada.");
        }
    });

    // Nueva tabla: Mensajes de grupo (MEJORADA)
    db.run(`CREATE TABLE IF NOT EXISTS group_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        sender TEXT,
        content TEXT,
        message_type TEXT DEFAULT 'text',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        file_name TEXT,
        file_size INTEGER,
        file_type TEXT,
        file_data TEXT,
        FOREIGN KEY (group_id) REFERENCES groups (id),
        FOREIGN KEY (sender) REFERENCES users (username)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'group_messages':", err.message);
        } else {
            console.log("Tabla 'group_messages' verificada/creada.");
            
            // Agregar columnas para archivos
            const columnsToAdd = [
                { name: 'content', type: 'TEXT' },
                { name: 'message_type', type: 'TEXT DEFAULT "text"' },
                { name: 'file_name', type: 'TEXT' },
                { name: 'file_size', type: 'INTEGER' },
                { name: 'file_type', type: 'TEXT' },
                { name: 'file_data', type: 'TEXT' }
            ];
            
            columnsToAdd.forEach(column => {
                db.run(`ALTER TABLE group_messages ADD COLUMN ${column.name} ${column.type}`, (err) => {
                    if (err && !err.message.includes('duplicate column name')) {
                        console.error(`Error al agregar columna '${column.name}':`, err.message);
                    }
                });
            });
        }
    });

    // Nueva tabla: Archivos escaneados (para tracking de antivirus)
    db.run(`CREATE TABLE IF NOT EXISTS scanned_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_hash TEXT UNIQUE,
        file_name TEXT,
        file_size INTEGER,
        scan_result TEXT,
        threat_detected BOOLEAN DEFAULT 0,
        scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        uploaded_by TEXT,
        FOREIGN KEY (uploaded_by) REFERENCES users (username)
    )`, (err) => {
        if (err) {
            console.error("Error al crear tabla 'scanned_files':", err.message);
        } else {
            console.log("Tabla 'scanned_files' verificada/creada.");
        }
    });
}

// Función para crear cuenta de administrador
function createAdminAccount() {
    const adminEmail = 'admin@uni.edu.pe';
    const adminPassword = 'UniAdmin2024!'; // Contraseña segura por defecto
    
    db.get('SELECT * FROM users WHERE username = ?', [adminEmail], async (err, user) => {
        if (err) {
            console.error('Error verificando cuenta admin:', err.message);
            return;
        }
        
        if (!user) {
            try {
                const hashedPassword = await bcrypt.hash(adminPassword, 10);
                db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                    [adminEmail, hashedPassword, 'admin'], function(err) {
                    if (err) {
                        console.error('Error creando cuenta admin:', err.message);
                    } else {
                        console.log(`Cuenta de administrador creada: ${adminEmail}`);
                        console.log(`Contraseña temporal: ${adminPassword}`);
                    }
                });
            } catch (error) {
                console.error('Error al hashear contraseña admin:', error);
            }
        }
    });
}

// Función para actualizar roles de usuarios basados en email
function updateUserRoles() {
    db.run(`UPDATE users SET role = CASE 
        WHEN username LIKE '%@uni.edu.pe' THEN 'teacher'
        WHEN username LIKE '%@uni.pe' THEN 'student'
        WHEN username = 'admin@uni.edu.pe' THEN 'admin'
        ELSE 'student'
    END WHERE role IS NULL OR role = 'student'`, (err) => {
        if (err) {
            console.error('Error actualizando roles:', err.message);
        } else {
            console.log('Roles de usuarios actualizados.');
        }
    });
}

// Función para determinar rol basado en email
function determineUserRole(email) {
    if (email === 'admin@uni.edu.pe') return 'admin';
    if (email.endsWith('@uni.edu.pe')) return 'teacher';
    if (email.endsWith('@uni.pe')) return 'student';
    return 'student';
}

// Función mejorada para calcular hash de archivo
function calculateFileHash(buffer) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Función para escanear archivo con VirusTotal MEJORADA
async function scanFileWithVirusTotal(fileBuffer, fileName) {
    if (!VIRUSTOTAL_API_KEY || VIRUSTOTAL_API_KEY === 'your_virustotal_api_key') {
        console.warn('VirusTotal API key no configurada, saltando escaneo');
        return { safe: true, message: 'Escaneo no disponible', threat: false };
    }

    const fileHash = calculateFileHash(fileBuffer);
    
    // Verificar si ya hemos escaneado este archivo
    return new Promise((resolve) => {
        db.get('SELECT * FROM scanned_files WHERE file_hash = ?', [fileHash], async (err, cachedScan) => {
            if (!err && cachedScan) {
                console.log(`Usando resultado de escaneo en caché para ${fileName}`);
                return resolve({
                    safe: !cachedScan.threat_detected,
                    message: cachedScan.scan_result,
                    threat: cachedScan.threat_detected
                });
            }
            
            // Escaneo nuevo
            try {
                const FormData = require('form-data');
                const form = new FormData();
                form.append('file', fileBuffer, fileName);

                console.log(`Escaneando archivo ${fileName} con VirusTotal...`);
                const response = await axios.post('https://www.virustotal.com/vtapi/v2/file/scan', form, {
                    headers: {
                        ...form.getHeaders(),
                        'apikey': VIRUSTOTAL_API_KEY
                    },
                    timeout: 30000
                });

                if (response.data && response.data.response_code === 1) {
                    // Esperar un momento para que VirusTotal procese
                    console.log('Esperando resultado del escaneo...');
                    await new Promise(resolve => setTimeout(resolve, 15000));
                    
                    const reportResponse = await axios.get('https://www.virustotal.com/vtapi/v2/file/report', {
                        params: {
                            apikey: VIRUSTOTAL_API_KEY,
                            resource: response.data.resource
                        },
                        timeout: 30000
                    });

                    if (reportResponse.data && reportResponse.data.response_code === 1) {
                        const positives = reportResponse.data.positives || 0;
                        const total = reportResponse.data.total || 1;
                        const threatDetected = positives > 0;
                        const scanResult = threatDetected 
                            ? `Malware detectado por ${positives}/${total} antivirus` 
                            : `Archivo limpio (${positives}/${total})`;
                        
                        // Guardar resultado en caché
                        db.run('INSERT OR REPLACE INTO scanned_files (file_hash, file_name, file_size, scan_result, threat_detected) VALUES (?, ?, ?, ?, ?)',
                            [fileHash, fileName, fileBuffer.length, scanResult, threatDetected]);
                        
                        resolve({ 
                            safe: !threatDetected, 
                            message: scanResult,
                            threat: threatDetected
                        });
                    } else {
                        // No hay reporte disponible aún
                        const defaultResult = 'Escaneo en progreso, archivo permitido temporalmente';
                        db.run('INSERT OR REPLACE INTO scanned_files (file_hash, file_name, file_size, scan_result, threat_detected) VALUES (?, ?, ?, ?, ?)',
                            [fileHash, fileName, fileBuffer.length, defaultResult, false]);
                        
                        resolve({ safe: true, message: defaultResult, threat: false });
                    }
                } else {
                    const defaultResult = 'No se pudo completar el escaneo, archivo permitido por defecto';
                    resolve({ safe: true, message: defaultResult, threat: false });
                }
            } catch (error) {
                console.error('Error en escaneo VirusTotal:', error.message);
                const errorResult = 'Error en escaneo, archivo permitido por defecto';
                resolve({ safe: true, message: errorResult, threat: false });
            }
        });
    });
}

// Middleware
app.use(express.static('public'));
app.use(bodyParser.json({ limit: '15mb' }));

// Configuración Multer
const storage = multer.memoryStorage();
const upload = multer({    
    storage: storage,
    limits: {    
        fileSize: 10 * 1024 * 1024 // 10MB límite
    },
    fileFilter: (req, file, cb) => {
        // Lista de extensiones prohibidas
        const forbiddenExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.js'];
        const fileExtension = path.extname(file.originalname).toLowerCase();
        
        if (forbiddenExtensions.includes(fileExtension)) {
            return cb(new Error('Tipo de archivo no permitido por seguridad'));
        }
        
        cb(null, true);
    }
});

// Mapa de usuarios conectados
const connectedUsers = {};

// Función auxiliar para generar chat_id consistente
function generateChatId(user1, user2) {
    return [user1, user2].sort().join('_');
}

// Función para extraer username desde Google ID token
function extractUsernameFromGoogleToken(payload) {
    const email = payload['email'];
    if (email && email.includes('@')) {
        return email.split('@')[0];
    }
    return `user_${payload['sub'].slice(-8)}`;
}

// --- Rutas HTTP ---
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const role = determineUserRole(username);
        
        db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
            [username, hashedPassword, role], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ message: 'El usuario ya existe.' });
                }
                console.error('Error al registrar usuario en DB:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor.' });
            }
            res.status(201).json({ message: 'Usuario registrado exitosamente.' });
            console.log(`Usuario '${username}' registrado exitosamente con rol '${role}'.`);
        });
    } catch (error) {
        console.error('Error al hashear contraseña:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error('Error DB al buscar usuario para login:', err.message);
            return res.status(500).json({ message: 'Error interno del servidor.' });
        }
        if (!user) {
            console.warn(`Intento de login fallido: Usuario '${username}' no encontrado.`);
            return res.status(401).json({ message: 'Usuario o contraseña incorrectos.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.warn(`Intento de login fallido: Contraseña incorrecta para '${username}'.`);
            return res.status(401).json({ message: 'Usuario o contraseña incorrectos.' });
        }

        const token = jwt.sign({ 
            id: user.id, 
            username: user.username, 
            role: user.role 
        }, JWT_SECRET, { expiresIn: '1h' });
        
        res.json({ 
            message: 'Login exitoso.', 
            token,
            user: {
                username: user.username,
                role: user.role
            }
        });
        console.log(`Usuario '${username}' logueado exitosamente. Token emitido.`);
    });
});

app.post('/google-login', async (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ message: 'Token de Google requerido.' });
    }

    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const googleId = payload['sub'];
        const email = payload['email'];
        const username = extractUsernameFromGoogleToken(payload);
        const role = determineUserRole(email);

        db.get('SELECT * FROM users WHERE googleId = ?', [googleId], async (err, user) => {
            if (err) {
                console.error('Error DB al buscar usuario por Google ID:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor.' });
            }

            if (user) {
                const jwtToken = jwt.sign({ 
                    id: user.id, 
                    username: user.username, 
                    role: user.role 
                }, JWT_SECRET, { expiresIn: '1h' });
                return res.json({ 
                    message: 'Login con Google exitoso.', 
                    token: jwtToken,
                    user: {
                        username: user.username,
                        role: user.role
                    }
                });
            } else {
                db.get('SELECT * FROM users WHERE username = ?', [username], async (err, existingUser) => {
                    if (err) {
                        console.error('Error DB al verificar username existente:', err.message);
                        return res.status(500).json({ message: 'Error interno del servidor.' });
                    }

                    let finalUsername = username;
                    if (existingUser) {
                        finalUsername = `${username}_${Math.floor(Math.random() * 10000)}`;
                    }

                    db.run('INSERT INTO users (username, googleId, role) VALUES (?, ?, ?)', 
                        [finalUsername, googleId, role], function(err) {
                        if (err) {
                            console.error('Error al registrar usuario de Google:', err.message);
                            return res.status(500).json({ message: 'Error al crear usuario.' });
                        }
                        const jwtToken = jwt.sign({ 
                            id: this.lastID, 
                            username: finalUsername, 
                            role: role 
                        }, JWT_SECRET, { expiresIn: '1h' });
                        res.json({ 
                            message: 'Usuario registrado con Google exitosamente.', 
                            token: jwtToken,
                            user: {
                                username: finalUsername,
                                role: role
                            }
                        });
                        console.log(`Usuario '${finalUsername}' registrado con Google (ID: ${googleId}) con rol '${role}'.`);
                    });
                });
            }
        });
    } catch (error) {
        console.error('Error al verificar token de Google:', error);
        res.status(401).json({ message: 'Token de Google inválido.' });
    }
});

// Ruta mejorada para subir archivos con escaneo antivirus
app.post('/upload-file', upload.single('file'), async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        if (!req.file) {
            return res.status(400).json({ message: 'No se subió archivo' });
        }

        try {
            console.log(`Iniciando análisis de archivo: ${req.file.originalname} (${req.file.size} bytes) por ${decoded.username}`);
            
            // Escanear archivo con VirusTotal
            const scanResult = await scanFileWithVirusTotal(req.file.buffer, req.file.originalname);
            
            // Registrar el escaneo en la base de datos
            const fileHash = calculateFileHash(req.file.buffer);
            db.run('INSERT OR REPLACE INTO scanned_files (file_hash, file_name, file_size, scan_result, threat_detected, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)',
                [fileHash, req.file.originalname, req.file.size, scanResult.message, scanResult.threat, decoded.username]);
            
            if (scanResult.threat) {
                console.log(`⚠️ ARCHIVO RECHAZADO: ${req.file.originalname} - ${scanResult.message}`);
                return res.status(400).json({ 
                    message: `Archivo rechazado: ${scanResult.message}`,
                    threat: true,
                    scanResult: scanResult.message
                });
            }

            const fileData = {
                name: req.file.originalname,
                size: req.file.size,
                type: req.file.mimetype,
                data: req.file.buffer.toString('base64')
            };

            console.log(`✅ Archivo aprobado: ${fileData.name} (${fileData.size} bytes) - ${scanResult.message}`);

            res.json({    
                message: 'Archivo subido y verificado exitosamente',
                file: fileData,
                scanResult: scanResult.message,
                safe: scanResult.safe
            });
        } catch (error) {
            console.error('Error procesando archivo:', error);
            res.status(500).json({ message: 'Error procesando archivo' });
        }
    });
});

// --- Nuevas rutas para el sistema de tickets MEJORADAS ---
app.get('/api/teachers', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        db.all(`SELECT username, availability FROM users WHERE role = 'teacher' ORDER BY username`, 
            (err, teachers) => {
            if (err) {
                console.error('Error obteniendo docentes:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }
            res.json(teachers);
        });
    });
});

app.put('/api/teachers/availability', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        if (decoded.role !== 'teacher') {
            return res.status(403).json({ message: 'Solo docentes pueden actualizar su disponibilidad' });
        }

        const { availability } = req.body;
        const validStates = ['available', 'busy', 'offline'];
        
        if (!validStates.includes(availability)) {
            return res.status(400).json({ message: 'Estado de disponibilidad inválido' });
        }

        db.run('UPDATE users SET availability = ? WHERE username = ?', 
            [availability, decoded.username], function(err) {
            if (err) {
                console.error('Error actualizando disponibilidad:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }
            
            res.json({ message: 'Disponibilidad actualizada exitosamente' });
            console.log(`Docente ${decoded.username} cambió disponibilidad a: ${availability}`);
        });
    });
});

app.post('/api/tickets', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        const { teacher_id, subject, question, priority = 'normal', category = 'general' } = req.body;
        if (!teacher_id || !subject || !question) {
            return res.status(400).json({ message: 'Todos los campos son requeridos' });
        }

        // Solo estudiantes pueden crear tickets
        if (decoded.role !== 'student') {
            return res.status(403).json({ message: 'Solo estudiantes pueden crear tickets' });
        }

        db.run(`INSERT INTO tickets (student_id, teacher_id, subject, question, priority, category) VALUES (?, ?, ?, ?, ?, ?)`,
            [decoded.username, teacher_id, subject, question, priority, category], function(err) {
            if (err) {
                console.error('Error creando ticket:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }
            
            res.status(201).json({ 
                message: 'Ticket creado exitosamente',
                ticketId: this.lastID 
            });
            
            console.log(`Nuevo ticket #${this.lastID} creado por ${decoded.username} para ${teacher_id}`);
            
            // Notificar al docente via Socket.IO si está conectado
            if (connectedUsers[teacher_id]) {
                io.to(connectedUsers[teacher_id]).emit('new_ticket', {
                    ticketId: this.lastID,
                    student: decoded.username,
                    subject: subject,
                    priority: priority
                });
            }
        });
    });
});

app.get('/api/tickets', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        let query, params;
        
        if (decoded.role === 'admin') {
            // Admin ve todos los tickets
            query = `SELECT t.*, u1.username as student_name, u2.username as teacher_name 
                     FROM tickets t 
                     LEFT JOIN users u1 ON t.student_id = u1.username 
                     LEFT JOIN users u2 ON t.teacher_id = u2.username 
                     ORDER BY t.created_at DESC`;
            params = [];
        } else if (decoded.role === 'teacher') {
            // Docentes ven tickets asignados a ellos
            query = `SELECT t.*, u.username as student_name 
                     FROM tickets t 
                     LEFT JOIN users u ON t.student_id = u.username 
                     WHERE t.teacher_id = ? 
                     ORDER BY t.created_at DESC`;
            params = [decoded.username];
        } else {
            // Estudiantes ven sus propios tickets
            query = `SELECT t.*, u.username as teacher_name 
                     FROM tickets t 
                     LEFT JOIN users u ON t.teacher_id = u.username 
                     WHERE t.student_id = ? 
                     ORDER BY t.created_at DESC`;
            params = [decoded.username];
        }

        db.all(query, params, (err, tickets) => {
            if (err) {
                console.error('Error obteniendo tickets:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }
            res.json(tickets);
        });
    });
});

app.put('/api/tickets/:id', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        const ticketId = req.params.id;
        const { status, response, priority, category } = req.body;

        // Solo docentes y admin pueden actualizar tickets
        if (decoded.role !== 'teacher' && decoded.role !== 'admin') {
            return res.status(403).json({ message: 'No tienes permisos para actualizar tickets' });
        }

        let query, params;
        if (response) {
            query = `UPDATE tickets SET status = ?, response = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
            params = [status || 'cerrado', response, ticketId];
        } else {
            query = `UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
            params = [status, ticketId];
        }

        // Si hay prioridad o categoría, incluirlas
        if (priority || category) {
            const updates = [];
            const newParams = [];
            
            if (status) {
                updates.push('status = ?');
                newParams.push(status);
            }
            if (response) {
                updates.push('response = ?');
                newParams.push(response);
            }
            if (priority) {
                updates.push('priority = ?');
                newParams.push(priority);
            }
            if (category) {
                updates.push('category = ?');
                newParams.push(category);
            }
            
            updates.push('updated_at = CURRENT_TIMESTAMP');
            newParams.push(ticketId);
            
            query = `UPDATE tickets SET ${updates.join(', ')} WHERE id = ?`;
            params = newParams;
        }

        db.run(query, params, function(err) {
            if (err) {
                console.error('Error actualizando ticket:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ message: 'Ticket no encontrado' });
            }
            
            res.json({ message: 'Ticket actualizado exitosamente' });
            
            console.log(`Ticket #${ticketId} actualizado por ${decoded.username}`);
            
            // Notificar al estudiante si está conectado
            db.get('SELECT student_id FROM tickets WHERE id = ?', [ticketId], (err, ticket) => {
                if (!err && ticket && connectedUsers[ticket.student_id]) {
                    io.to(connectedUsers[ticket.student_id]).emit('ticket_updated', {
                        ticketId: ticketId,
                        status: status,
                        response: response
                    });
                }
            });
        });
    });
});

app.delete('/api/tickets/:id', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        // Solo admin puede eliminar tickets
        if (decoded.role !== 'admin') {
            return res.status(403).json({ message: 'Solo administradores pueden eliminar tickets' });
        }

        const ticketId = req.params.id;

        db.run('DELETE FROM tickets WHERE id = ?', [ticketId], function(err) {
            if (err) {
                console.error('Error eliminando ticket:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ message: 'Ticket no encontrado' });
            }
            
            res.json({ message: 'Ticket eliminado exitosamente' });
            console.log(`Ticket #${ticketId} eliminado por admin ${decoded.username}`);
        });
    });
});

// --- Nuevas rutas para el sistema de grupos ---
app.get('/api/groups', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        const query = `
            SELECT g.*, gm.role as user_role, 
                   COUNT(gm2.id) as member_count
            FROM groups g
            JOIN group_members gm ON g.id = gm.group_id
            LEFT JOIN group_members gm2 ON g.id = gm2.group_id
            WHERE gm.user_id = ?
            GROUP BY g.id, gm.role
            ORDER BY g.created_at DESC
        `;

        db.all(query, [decoded.username], (err, groups) => {
            if (err) {
                console.error('Error obteniendo grupos:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }
            res.json(groups);
        });
    });
});

app.post('/api/groups', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        const { name, description, max_members = 50, is_private = false } = req.body;
        if (!name || name.trim() === '') {
            return res.status(400).json({ message: 'El nombre del grupo es requerido' });
        }

        db.run('INSERT INTO groups (name, description, created_by, max_members, is_private) VALUES (?, ?, ?, ?, ?)',
            [name.trim(), description?.trim() || null, decoded.username, max_members, is_private], function(err) {
            if (err) {
                console.error('Error creando grupo:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }

            const groupId = this.lastID;

            // Añadir al creador como administrador del grupo
            db.run('INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
                [groupId, decoded.username, 'admin'], (err) => {
                if (err) {
                    console.error('Error añadiendo creador al grupo:', err.message);
                    return res.status(500).json({ message: 'Error interno del servidor' });
                }

                res.status(201).json({
                    message: 'Grupo creado exitosamente',
                    groupId: groupId
                });

                console.log(`Grupo "${name}" creado por ${decoded.username} (ID: ${groupId})`);
            });
        });
    });
});

app.get('/api/groups/:id/messages', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        const groupId = req.params.id;

        // Verificar que el usuario es miembro del grupo
        db.get('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?', 
            [groupId, decoded.username], (err, membership) => {
            if (err) {
                console.error('Error verificando membresía:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }

            if (!membership) {
                return res.status(403).json({ message: 'No eres miembro de este grupo' });
            }

            // Obtener mensajes del grupo
            db.all(`SELECT * FROM group_messages WHERE group_id = ? ORDER BY timestamp ASC LIMIT 50`,
                [groupId], (err, messages) => {
                if (err) {
                    console.error('Error obteniendo mensajes del grupo:', err.message);
                    return res.status(500).json({ message: 'Error interno del servidor' });
                }
                res.json(messages);
            });
        });
    });
});

app.post('/api/groups/:id/messages', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        const groupId = req.params.id;
        const { content } = req.body;

        if (!content || content.trim() === '') {
            return res.status(400).json({ message: 'El contenido del mensaje es requerido' });
        }

        // Verificar que el usuario es miembro del grupo
        db.get('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?', 
            [groupId, decoded.username], (err, membership) => {
            if (err) {
                console.error('Error verificando membresía:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }

            if (!membership) {
                return res.status(403).json({ message: 'No eres miembro de este grupo' });
            }

            // Insertar mensaje
            db.run('INSERT INTO group_messages (group_id, sender, content) VALUES (?, ?, ?)',
                [groupId, decoded.username, content.trim()], function(err) {
                if (err) {
                    console.error('Error guardando mensaje del grupo:', err.message);
                    return res.status(500).json({ message: 'Error interno del servidor' });
                }

                res.status(201).json({
                    message: 'Mensaje enviado exitosamente',
                    messageId: this.lastID
                });

                console.log(`Mensaje enviado al grupo ${groupId} por ${decoded.username}`);

                // Aquí se podría implementar Socket.IO para mensajes en tiempo real
            });
        });
    });
});

// --- Ruta para estadísticas de archivos escaneados (Admin) ---
app.get('/api/scan-stats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }

        if (decoded.role !== 'admin') {
            return res.status(403).json({ message: 'Solo administradores pueden ver estadísticas' });
        }

        const statsQuery = `
            SELECT 
                COUNT(*) as total_scanned,
                SUM(CASE WHEN threat_detected = 1 THEN 1 ELSE 0 END) as threats_detected,
                COUNT(DISTINCT uploaded_by) as unique_uploaders,
                AVG(file_size) as avg_file_size
            FROM scanned_files
        `;

        db.get(statsQuery, [], (err, stats) => {
            if (err) {
                console.error('Error obteniendo estadísticas:', err.message);
                return res.status(500).json({ message: 'Error interno del servidor' });
            }

            // Obtener archivos más recientes escaneados
            db.all('SELECT * FROM scanned_files ORDER BY scan_date DESC LIMIT 10', [], (err, recentScans) => {
                if (err) {
                    console.error('Error obteniendo escaneos recientes:', err.message);
                    return res.status(500).json({ message: 'Error interno del servidor' });
                }

                res.json({
                    stats: {
                        ...stats,
                        avg_file_size: Math.round(stats.avg_file_size || 0)
                    },
                    recentScans
                });
            });
        });
    });
});

// Middleware de autenticación para Socket.IO
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        console.warn('Conexión Socket.IO denegada: No se proporcionó token.');
        return next(new Error('Autenticación requerida. No se proporcionó token.'));
    }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('Error de verificación de token JWT para Socket.IO:', err.message);
            return next(new Error('Token inválido o expirado.'));
        }
        socket.user = decoded;
        next();
    });
});

// Lógica mejorada de Socket.IO
io.on('connection', (socket) => {
    console.log(`Usuario conectado: ${socket.user.username} (ID: ${socket.id}, Rol: ${socket.user.role})`);
    connectedUsers[socket.user.username] = socket.id;

    // Notifica usuarios online con información de roles
    const onlineUsersWithRoles = Object.keys(connectedUsers).map(username => {
        // Buscar el rol del usuario
        return new Promise((resolve) => {
            db.get('SELECT role FROM users WHERE username = ?', [username], (err, user) => {
                resolve({
                    username,
                    role: user ? user.role : 'student'
                });
            });
        });
    });

    Promise.all(onlineUsersWithRoles).then(users => {
        io.emit('online_users', users);
    });

    socket.on('send_public_key', (publicKey) => {
        if (socket.user && socket.user.username && publicKey) {
            console.log(`Recibida clave pública de ${socket.user.username}. Almacenando en DB...`);
            db.run('UPDATE users SET publicKey = ? WHERE username = ?', [publicKey, socket.user.username], function(err) {
                if (err) {
                    console.error(`Error al guardar clave pública para ${socket.user.username} en DB:`, err.message);
                } else {
                    console.log(`Clave pública guardada exitosamente para ${socket.user.username}.`);
                }
            });
        }
    });

    socket.on('search_users', (searchTerm) => {
        if (!searchTerm || searchTerm.length < 2) {
            socket.emit('search_results', []);
            return;
        }
        
        const currentUser = socket.user.username;
        db.all(`
            SELECT username, role FROM users 
            WHERE username LIKE ? AND username != ? 
            AND username NOT IN (
                SELECT user2_username FROM friendships WHERE user1_username = ?
                UNION
                SELECT user1_username FROM friendships WHERE user2_username = ?
            )
            AND username NOT IN (
                SELECT receiver_username FROM friend_requests 
                WHERE requester_username = ? AND status = 'pending'
            )
            LIMIT 10
        `, [`%${searchTerm}%`, currentUser, currentUser, currentUser, currentUser], (err, rows) => {
            if (err) {
                console.error('Error al buscar usuarios:', err.message);
                socket.emit('search_results', []);
            } else {
                socket.emit('search_results', rows);
            }
        });
    });

    socket.on('send_friend_request', (targetUsername) => {
        const requester = socket.user.username;
        
        if (requester === targetUsername) {
            socket.emit('error_message', 'No puedes enviarte una solicitud a ti mismo.');
            return;
        }

        db.get(`
            SELECT * FROM friend_requests 
            WHERE (requester_username = ? AND receiver_username = ?) 
            OR (requester_username = ? AND receiver_username = ?)
        `, [requester, targetUsername, targetUsername, requester], (err, existingRequest) => {
            if (err) {
                console.error('Error al verificar solicitud existente:', err.message);
                socket.emit('error_message', 'Error al enviar solicitud.');
                return;
            }

            if (existingRequest) {
                socket.emit('error_message', 'Ya existe una solicitud de amistad con este usuario.');
                return;
            }

            db.get(`
                SELECT * FROM friendships 
                WHERE (user1_username = ? AND user2_username = ?) 
                OR (user1_username = ? AND user2_username = ?)
            `, [requester, targetUsername, targetUsername, requester], (err, friendship) => {
                if (err) {
                    console.error('Error al verificar amistad:', err.message);
                    socket.emit('error_message', 'Error al enviar solicitud.');
                    return;
                }

                if (friendship) {
                    socket.emit('error_message', 'Ya eres amigo de este usuario.');
                    return;
                }

                db.run('INSERT INTO friend_requests (requester_username, receiver_username) VALUES (?, ?)', 
                    [requester, targetUsername], function(err) {
                    if (err) {
                        console.error('Error al crear solicitud de amistad:', err.message);
                        socket.emit('error_message', 'Error al enviar solicitud.');
                    } else {
                        socket.emit('friend_request_sent', targetUsername);
                        
                        if (connectedUsers[targetUsername]) {
                            io.to(connectedUsers[targetUsername]).emit('friend_request_received', {
                                requester: requester,
                                id: this.lastID
                            });
                        }
                        console.log(`Solicitud de amistad enviada de ${requester} a ${targetUsername}`);
                    }
                });
            });
        });
    });

    socket.on('get_friend_requests', () => {
        const username = socket.user.username;
        db.all('SELECT * FROM friend_requests WHERE receiver_username = ? AND status = "pending"', 
            [username], (err, rows) => {
            if (err) {
                console.error('Error al obtener solicitudes de amistad:', err.message);
                socket.emit('friend_requests_list', []);
            } else {
                socket.emit('friend_requests_list', rows);
            }
        });
    });

    socket.on('respond_friend_request', (data) => {
        const { requestId, accept } = data;
        const receiver = socket.user.username;

        db.get('SELECT * FROM friend_requests WHERE id = ? AND receiver_username = ?', 
            [requestId, receiver], (err, request) => {
            if (err || !request) {
                console.error('Error al buscar solicitud:', err);
                socket.emit('error_message', 'Solicitud no encontrada.');
                return;
            }

            if (accept) {
                const user1 = request.requester_username;
                const user2 = receiver;
                const sortedUsers = [user1, user2].sort();

                db.run('INSERT INTO friendships (user1_username, user2_username) VALUES (?, ?)',
                    [sortedUsers[0], sortedUsers[1]], function(err) {
                    if (err) {
                        console.error('Error al crear amistad:', err.message);
                        socket.emit('error_message', 'Error al aceptar solicitud.');
                        return;
                    }

                    db.run('UPDATE friend_requests SET status = "accepted" WHERE id = ?', [requestId]);
                    
                    socket.emit('friend_request_accepted', user1);
                    
                    if (connectedUsers[user1]) {
                        io.to(connectedUsers[user1]).emit('friend_request_response', {
                            user: user2,
                            accepted: true
                        });
                    }

                    console.log(`Amistad creada entre ${user1} y ${user2}`);
                });
            } else {
                db.run('UPDATE friend_requests SET status = "rejected" WHERE id = ?', [requestId], (err) => {
                    if (err) {
                        console.error('Error al rechazar solicitud:', err.message);
                    } else {
                        socket.emit('friend_request_rejected', request.requester_username);
                        
                        if (connectedUsers[request.requester_username]) {
                            io.to(connectedUsers[request.requester_username]).emit('friend_request_response', {
                                user: receiver,
                                accepted: false
                            });
                        }
                    }
                });
            }
        });
    });

    socket.on('get_friends_list', () => {
        const username = socket.user.username;
        db.all(`
            SELECT 
                CASE 
                    WHEN user1_username = ? THEN user2_username 
                    ELSE user1_username 
                END as friend_username,
                created_at
            FROM friendships 
            WHERE user1_username = ? OR user2_username = ?
            ORDER BY created_at DESC
        `, [username, username, username], (err, rows) => {
            if (err) {
                console.error('Error al obtener lista de amigos:', err.message);
                socket.emit('friends_list', []);
            } else {
                // Obtener información adicional de roles para cada amigo
                const friendPromises = rows.map(row => {
                    return new Promise((resolve) => {
                        db.get('SELECT role FROM users WHERE username = ?', [row.friend_username], (err, user) => {
                            resolve({
                                username: row.friend_username,
                                isOnline: !!connectedUsers[row.friend_username],
                                created_at: row.created_at,
                                role: user ? user.role : 'student'
                            });
                        });
                    });
                });

                Promise.all(friendPromises).then(friends => {
                    socket.emit('friends_list', friends);
                });
            }
        });
    });

    socket.on('request_public_key', (targetUsername) => {
        console.log(`${socket.user.username} solicita clave pública de ${targetUsername}.`);
        
        db.get(`
            SELECT * FROM friendships 
            WHERE (user1_username = ? AND user2_username = ?) 
            OR (user1_username = ? AND user2_username = ?)
        `, [socket.user.username, targetUsername, targetUsername, socket.user.username], (err, friendship) => {
            if (err) {
                console.error('Error al verificar amistad:', err.message);
                socket.emit('error_message', 'Error al verificar amistad.');
                return;
            }

            if (!friendship) {
                socket.emit('error_message', `No eres amigo de ${targetUsername}.`);
                return;
            }

            db.get('SELECT publicKey FROM users WHERE username = ?', [targetUsername], (err, row) => {
                if (err) {
                    console.error(`Error DB al obtener clave pública para ${targetUsername}:`, err.message);
                    socket.emit('error_message', `Error al obtener clave pública para ${targetUsername}.`);
                    return;
                }
                if (row && row.publicKey) {
                    console.log(`Clave pública de ${targetUsername} encontrada. Enviando a ${socket.user.username}.`);
                    socket.emit('receive_public_key', { username: targetUsername, publicKey: row.publicKey });
                } else {
                    console.warn(`Clave pública no encontrada para ${targetUsername}.`);
                    socket.emit('error_message', `Clave pública no encontrada para ${targetUsername}.`);
                }
            });
        });
    });

    socket.on('get_chat_history', (friendUsername) => {
        const currentUser = socket.user.username;
        const chatId = generateChatId(currentUser, friendUsername);

        db.get(`
            SELECT * FROM friendships 
            WHERE (user1_username = ? AND user2_username = ?) 
            OR (user1_username = ? AND user2_username = ?)
        `, [currentUser, friendUsername, friendUsername, currentUser], (err, friendship) => {
            if (err || !friendship) {
                socket.emit('error_message', 'No tienes acceso a este chat.');
                return;
            }

            db.all(`
                SELECT 
                    id, chat_id, sender, receiver, encryptedMessage, iv, 
                    message_type, timestamp, file_name, file_size, file_type, file_data
                FROM messages 
                WHERE chat_id = ? 
                ORDER BY timestamp ASC 
                LIMIT 50
            `, [chatId], (err, messages) => {
                if (err) {
                    console.error('Error al obtener historial de chat:', err.message);
                    socket.emit('chat_history', []);
                } else {
                    console.log(`Enviando historial de ${messages.length} mensajes para chat ${chatId}`);
                    socket.emit('chat_history', messages);
                }
            });
        });
    });

    socket.on('private_message', async (data) => {
        const { receiver, encryptedMessage, iv, messageType, fileData } = data; 
        const sender = socket.user.username;
        const chatId = generateChatId(sender, receiver);

        console.log(`Recibido private_message de ${sender} para ${receiver}. IV: ${iv}. Tipo: ${messageType || 'text'}`);

        db.get(`
            SELECT * FROM friendships 
            WHERE (user1_username = ? AND user2_username = ?) 
            OR (user1_username = ? AND user2_username = ?)
        `, [sender, receiver, receiver, sender], (err, friendship) => {
            if (err || !friendship) {
                socket.emit('error_message', 'No puedes enviar mensajes a este usuario.');
                return;
            }

            if (connectedUsers[receiver]) {
                io.to(connectedUsers[receiver]).emit('private_message', {
                    sender: sender,
                    encryptedMessage: encryptedMessage,
                    iv: iv,
                    chatId: chatId,
                    messageType: messageType || 'text',
                    fileData: fileData
                });
                console.log(`Mensaje reenviado de ${sender} a ${receiver} (online).`);
            }

            const query = `INSERT INTO messages 
                (chat_id, sender, receiver, encryptedMessage, iv, message_type, file_name, file_size, file_type, file_data) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
            
            const params = [
                chatId, 
                sender, 
                receiver, 
                encryptedMessage, 
                iv,
                messageType || 'text',
                fileData ? fileData.name : null,
                fileData ? fileData.size : null,
                fileData ? fileData.type : null,
                fileData ? fileData.data : null
            ];

            db.run(query, params, function(err) {
                if (err) {
                    console.error('Error al guardar mensaje en DB:', err.message);
                    socket.emit('error_message', 'Error al guardar mensaje.');
                } else {
                    console.log(`Mensaje guardado en DB (ID: ${this.lastID}, Tipo: ${messageType || 'text'}).`);
                }
            });
        });
    });

    socket.on('disconnect', () => {
        console.log(`Usuario desconectado: ${socket.user.username} (ID: ${socket.id})`);
        delete connectedUsers[socket.user.username];
        
        // Actualizar lista de usuarios online
        const onlineUsersWithRoles = Object.keys(connectedUsers).map(username => {
            return new Promise((resolve) => {
                db.get('SELECT role FROM users WHERE username = ?', [username], (err, user) => {
                    resolve({
                        username,
                        role: user ? user.role : 'student'
                    });
                });
            });
        });

        Promise.all(onlineUsersWithRoles).then(users => {
            io.emit('online_users', users);
        });
        
        io.emit('user_offline', socket.user.username);
    });
});

// Iniciar servidor HTTPS
server.listen(port, () => {
    console.log(`🚀 Servidor HTTPS escuchando en https://localhost:${port}`);
    console.log(`📱 Accede a la aplicación en tu navegador vía HTTPS para que la criptografía funcione.`);
    console.log(`🌐 Si estás en otra máquina, usa https://[TU_IP_LOCAL]:${port}`);
    console.log(`🔒 Recuerda aceptar la advertencia de seguridad del navegador por el certificado autofirmado.`);
    console.log(`🛡️ Sistema de análisis antivirus: ${VIRUSTOTAL_API_KEY !== 'your_virustotal_api_key' ? 'Activo' : 'Inactivo'}`);
    console.log(`👥 Sistema de tickets y grupos: Activo`);
});