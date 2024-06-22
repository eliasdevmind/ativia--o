from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from flask_mysqldb import MySQL
from itsdangerous import URLSafeTimedSerializer
import bcrypt
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

mail = Mail(app)
mysql = MySQL(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/', methods=['GET', 'POST'])
def solicitar_redefinicao():
    if request.method == 'POST':
        email = request.form['email']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        usuario = cursor.fetchone()
        if usuario:
            token = s.dumps(email, salt='email-confirm')
            link = url_for('redefinir_senha', token=token, _external=True)
            msg = Message('Solicitação de Redefinição de Senha', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Olá {usuario["username"]},\n\nPor favor, use o seguinte link para redefinir sua senha: {link}'
            mail.send(msg)
            flash('Um link de redefinição de senha foi enviado para seu email.', 'info')
        else:
            flash('Email não encontrado!', 'danger')
        cursor.close()
    return render_template('solicitar_redefinicao.html')

@app.route('/redefinir_senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)  # Link válido por 1 hora (3600 segundos)
    except:
        flash('O link é inválido ou expirou.', 'danger')
        return redirect(url_for('solicitar_redefinicao'))
    
    if request.method == 'POST':
        senha = request.form['senha']
        senha_hashed = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE users SET hashed_password=%s WHERE email=%s", (senha_hashed, email))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('senha_redefinida'))
    
    return render_template('redefinir_senha.html')

@app.route('/senha_redefinida')
def senha_redefinida():
    return render_template('senha_redefinida.html')

if __name__ == '__main__':
    app.run(port=8000)
