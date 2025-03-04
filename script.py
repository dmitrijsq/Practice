from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from scapy.all import sniff, IP, TCP, UDP
import threading
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'network_traffic.db'

# Инициализация базы данных
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                protocol TEXT NOT NULL,
                port INTEGER,
                length INTEGER NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()

# Обработка пакетов
def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet.sprintf('%IP.proto%')
        port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
        length = len(packet)
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO packets (timestamp, source, destination, protocol, port, length)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, ip_src, ip_dst, protocol, port, length))
            conn.commit()

# Запуск сниффера
def start_sniffing():
    sniff(prn=packet_callback, store=False)

# Декоратор для проверки токена
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or token != 'Bearer dummy_token':  
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# Главная страница
@app.route('/')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('index.html')

# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()  # Получаем JSON данные
        username = data.get('username')
        password = data.get('password')
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
        
        if user and check_password_hash(user[1], password):
            session['user'] = username
            return jsonify({"token": "dummy_token"})  # Возвращаем токен 
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    return render_template('login.html')

# Выход
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# Получение данных
@app.route('/data')
@token_required
def data():
    source = request.args.get('source')
    destination = request.args.get('destination')
    protocol = request.args.get('protocol')
    port = request.args.get('port')
    
    query = 'SELECT * FROM packets WHERE 1=1'
    params = []
    if source:
        query += ' AND source = ?'
        params.append(source)
    if destination:
        query += ' AND destination = ?'
        params.append(destination)
    if protocol:
        # Преобразуем строковый протокол в числовой 
        protocol_map = {"TCP": "6", "UDP": "17", "ICMP": "1", "HTTP": "80", "HTTPS": "443"}
        protocol_num = protocol_map.get(protocol, protocol)
        query += ' AND protocol = ?'
        params.append(protocol_num)
    if port:
        query += ' AND port = ?'
        params.append(port)
    query += ' ORDER BY timestamp DESC LIMIT 100'
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        packets = cursor.fetchall()
    
    result = [{"id": p[0], "timestamp": p[1], "source": p[2], "destination": p[3], "protocol": p[4], "port": p[5], "length": p[6]} for p in packets]
    return jsonify(result)

# Регистрация
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    hashed_password = generate_password_hash(password)
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Username already exists"}), 400
    
    return jsonify({"message": "User registered successfully"}), 201

# Проверка авторизации
def is_logged_in():
    return 'user' in session

# Запуск приложения
if __name__ == '__main__':
    threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=True)