from flask import Flask, request, jsonify
import bcrypt
import psycopg2
import json
import os
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity

app = Flask(__name__)

# Configuração do banco de dados usando variáveis de ambiente
db_config = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "iot_auth_user"),
    "password": os.getenv("DB_PASSWORD", "password"),
    "dbname": os.getenv("DB_NAME", "iot_auth"),
    "port": os.getenv("DB_PORT", "5432")
}

# Conectar ao banco de dados
def get_db_connection():
    try:
        return psycopg2.connect(**db_config)
    except psycopg2.Error as err:
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

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash FROM users WHERE username = %s AND role = 'admin'", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):  
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

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash FROM devices WHERE username = %s", (username,))
    device = cursor.fetchone()
    cursor.close()
    conn.close()

    if device and bcrypt.checkpw(password.encode('utf-8'), device[1].encode('utf-8')):  
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

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO devices (device_name, username, password_hash) VALUES (%s, %s, %s)",
                       (device_name, username, hashed_password))
        conn.commit()
        return jsonify({"message": "Dispositivo registrado com sucesso!"}), 201
    except psycopg2.Error as err:
        return jsonify({"error": str(err)}), 400
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
