from flask import Flask, request, jsonify
import sqlite3
from bcrypt import hashpw, gensalt, checkpw

# Configuración de la aplicación Flask
app = Flask(__name__)
DATABASE = 'usuarios.db'

# Crear la base de datos y la tabla si no existen
def inicializar_bd():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            apellido TEXT NOT NULL,
            registro TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Ruta para registrar usuarios
@app.route('/registro', methods=['POST'])
def registrar_usuario():
    data = request.json
    nombre = data.get('nombre')
    apellido = data.get('apellido')
    registro = data.get('registro')
    password = data.get('password')
    
    # Hash de la contraseña
    password_hash = hashpw(password.encode('utf-8'), gensalt())

    # Guardar el usuario en la base de datos
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO usuarios (nombre, apellido, registro, password_hash) VALUES (?, ?, ?, ?)
    ''', (nombre, apellido, registro, password_hash))
    conn.commit()
    conn.close()

    return jsonify({'mensaje': 'Usuario registrado con éxito'}), 201

# Ruta para validar el usuario
@app.route('/validar', methods=['POST'])
def validar_usuario():
    data = request.json
    nombre = data.get('nombre')
    apellido = data.get('apellido')
    password = data.get('password')

    # Validar el usuario
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT password_hash FROM usuarios WHERE nombre=? AND apellido=?
    ''', (nombre, apellido))
    result = cursor.fetchone()
    conn.close()

    if result and checkpw(password.encode('utf-8'), result[0]):
        return jsonify({'mensaje': 'Usuario validado correctamente'}), 200
    else:
        return jsonify({'mensaje': 'Error en la validación de usuario'}), 401

if __name__ == '__main__':
    inicializar_bd()
    app.run(host='0.0.0.0', port=7890)
