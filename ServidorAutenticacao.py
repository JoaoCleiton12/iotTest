from flask import Flask, request, jsonify
import bcrypt
import mysql.connector
import json
import os
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity

app = Flask(__name__)

# Configuração do banco de dados usando variáveis de ambiente
db_config = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "root"),
    "database": os.getenv("DB_NAME", "IoT_Auth"),
}

# Conectar ao banco de dados
try:
    db = mysql.connector.connect(**db_config)
except mysql.connector.Error as err:
    print(f"Erro ao conectar ao banco de dados: {err}")
    exit(1)

# Configuração do JWT
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "chave_super_secreta")
jwt = JWTManager(app)

# 🔹 1. LOGIN DO ADMINISTRADOR
@app.route("/login_admin", methods=["POST"])
def login_admin():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Usuário e senha são obrigatórios"}), 400

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT username, password_hash FROM users WHERE username = %s AND role = 'admin'", (username,))
    user = cursor.fetchone()
    cursor.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):  
        access_token = create_access_token(identity=json.dumps({"username": username, "role": "admin"}))
        return jsonify({"access_token": access_token}), 200

    return jsonify({"error": "Credenciais inválidas"}), 401

# 🔹 2. LOGIN DE DISPOSITIVO
@app.route("/login_device", methods=["POST"])
def login_device():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Usuário e senha são obrigatórios"}), 400

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT username, password_hash FROM devices WHERE username = %s", (username,))
    device = cursor.fetchone()
    cursor.close()

    if device and bcrypt.checkpw(password.encode('utf-8'), device["password_hash"].encode('utf-8')):  
        access_token = create_access_token(identity=json.dumps({"username": username, "role": "device"}))
        return jsonify({"access_token": access_token}), 200

    return jsonify({"error": "Credenciais inválidas"}), 401

# 🔹 3. REGISTRO DE DISPOSITIVO (SOMENTE ADMIN)
@app.route("/register_device", methods=["POST"])
@jwt_required()
def register_device():
    data = request.json
    device_name = data.get("device_name")
    username = data.get("username")
    password = data.get("password")

    if not device_name or not username or not password:
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    # Pegando o usuário autenticado
    current_user = json.loads(get_jwt_identity())

    # Verifica se é um admin
    if current_user.get("role") != "admin":
        return jsonify({"error": "Apenas administradores podem registrar dispositivos"}), 403

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO devices (device_name, username, password_hash) VALUES (%s, %s, %s)",
                       (device_name, username, hashed_password))
        db.commit()
        return jsonify({"message": "Dispositivo registrado com sucesso!"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 400
    finally:
        cursor.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
