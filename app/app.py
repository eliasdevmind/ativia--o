from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os

# Carregar variáveis de ambiente
load_dotenv()

MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_DB = os.getenv("MYSQL_DB")
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

# Verificar se todas as variáveis de ambiente estão definidas
if not all([MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, SECRET_KEY, MAIL_USERNAME, MAIL_PASSWORD]):
    raise ValueError("Por favor, defina todas as variáveis de ambiente necessárias.")

# Configuração do Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuração do SQLAlchemy
db = SQLAlchemy(app)

# Configuração do Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
mail = Mail(app)

# Contexto de hashing de senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuração do serializer para token seguro com tempo de expiração
serializer = URLSafeTimedSerializer(SECRET_KEY)

# Modelo de usuário
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    hashed_password = db.Column(db.String(100), nullable=False)

# Rotas
@app.route('/')
def index():
    return 'Sistema de Redefinição de Senha'

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Gerar token com tempo de expiração de 5 minutos
            token = serializer.dumps(email, salt='reset-password')
            
            # Construir o link de redefinição de senha
            reset_link = url_for('reset_token', token=token, _external=True)
            
            # Enviar e-mail com o link de redefinição
            send_password_reset_email(user.email, reset_link)
            return render_template('reset_sent.html')
        else:
            return render_template('reset_sent.html')
    return render_template('reset_request.html')

@app.route('/reset-token/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=300)  # 300 segundos = 5 minutos
    except Exception as e:
        print('Token inválido ou expirado:', e)
        return render_template('reset_invalid.html')

    if request.method == 'POST':
        new_password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            # Atualizar senha no banco de dados
            user.hashed_password = get_password_hash(new_password)
            db.session.commit()
            return render_template('reset_success.html')
        else:
            return render_template('reset_invalid.html')
    
    return render_template('reset_token.html')

def send_password_reset_email(email, reset_link):
    subject = "Redefinição de Senha - Sistema"
    html_body = f"""
    <p>Você solicitou a redefinição de senha para o sistema.</p>
    <p>Para redefinir sua senha, clique no link abaixo:</p>
    <p><a href="{reset_link}">{reset_link}</a></p>
    <p>Se você não solicitou essa redefinição, por favor, ignore este e-mail.</p>
    """
    msg = Message(subject, recipients=[email], html=html_body)
    mail.send(msg)

# Funções auxiliares
def get_password_hash(password):
    return pwd_context.hash(password)

if __name__ == '__main__':
    app.run(debug=True)

