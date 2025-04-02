from flask import Flask, request, jsonify
import bcrypt
import psycopg2
import json
import os
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity

app = Flask(__name__)

# Configuração correta do banco de dados
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://iot_auth_user:Y7Ogpp0VgDNakTSBP16nVSIBj0jsUKbr@dpg-cvmj25buibrs73bhukrg-a/iot_auth")

def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except psycopg2.Error as err:
        print(f"Erro ao conectar ao banco de dados: {err}")
        exit(1)

# Configuração do JWT
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "chave_super_secreta")
jwt = JWTManager(app)

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Servidor Flask está rodando!"}), 200

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

@app.route("/register_device", methods=["POST"])
@jwt_required()
def register_device():
    data = request.json
    device_name = data.get("device_name")
    username = data.get("username")
    password = data.get("password")

    if not device_name or not username or not password:
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    current_user = json.loads(get_jwt_identity())
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

@app.route("/get_broker_info", methods=["GET"])
@jwt_required()
def get_broker_info():
    # Identidade do usuário autenticado via JWT
    current_user = json.loads(get_jwt_identity())

    # Apenas dispositivos podem acessar essa rota
    if current_user.get("role") != "device":
        return jsonify({"error": "Acesso negado"}), 403

    # Retorna as configurações do broker Mosquitto Público
    return jsonify({
        "mqtt_ip": "test.mosquitto.org",
        "mqtt_port": 8883,
        "xxtea_key": "chave_secreta"
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, debug=True, ssl_context=("cert.pem", "key.pem"))
