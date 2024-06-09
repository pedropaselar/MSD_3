from flask import Flask, request, jsonify
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from models import db, User
import logging
from flasgger import Swagger
from flask_mail import Mail, Message
import time

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
swagger = Swagger(app)
mail = Mail(app)

# Middleware de Auditoria
class AuditMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        request_start_time = time.time()
        request_data = environ
        def custom_start_response(status, headers, exc_info=None):
            response_time = time.time() - request_start_time
            app.logger.info(f"Method: {request_data['REQUEST_METHOD']}, "
                            f"Path: {request_data['PATH_INFO']}, "
                            f"Status: {status}, "
                            f"Response Time: {response_time} seconds")
            return start_response(status, headers, exc_info)

        return self.app(environ, custom_start_response)

app.wsgi_app = AuditMiddleware(app.wsgi_app)

# Configuração de logging
logging.basicConfig(filename='error.log', level=logging.DEBUG)

# Função de envio de email
def send_email(subject, recipient, body):
    msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[recipient])
    msg.body = body
    mail.send(msg)

@app.route('/', methods=['POST'])
def create_user():
    """
    Criação de Usuário
    ---
    parameters:
      - name: username
        in: body
        type: string
        required: true
        description: Nome do usuário
      - name: password
        in: body
        type: string
        required: true
        description: Senha do usuário
    responses:
      201:
        description: Usuário criado com sucesso
      400:
        description: Erro na criação do usuário
    """
    try:
        data = request.get_json()
        app.logger.debug(f"Data received: {data}")
        username = data.get('username')
        password = data.get('password')

        # Validações adicionais
        if not username or not password:
            app.logger.error("Username or password not provided")
            return jsonify({"message": "Username and password are required"}), 400
        
        if len(username) < 5:
            app.logger.error("Username too short")
            return jsonify({"message": "Username must be at least 5 characters long"}), 400

        if len(password) < 8:
            app.logger.error("Password too short")
            return jsonify({"message": "Password must be at least 8 characters long"}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({"message": "Username already exists"}), 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f"User {username} created successfully")
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        app.logger.error(f"Error creating user: {e}")
        return jsonify({"message": "Internal server error"}), 500

@app.route('/', methods=['PUT'])
def login_user():
    """
    Login de Usuário
    ---
    parameters:
      - name: username
        in: body
        type: string
        required: true
        description: Nome do usuário
      - name: password
        in: body
        type: string
        required: true
        description: Senha do usuário
    responses:
      200:
        description: Login realizado com sucesso
      401:
        description: Nome de usuário ou senha inválidos
      403:
        description: Usuário bloqueado ou precisa trocar a senha
    """
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()

        if not user:
            app.logger.warning(f"Failed login attempt for non-existent user: {username}")
            return jsonify({"message": "Invalid username or password"}), 401
        
        if user.blocked:
            app.logger.warning(f"Blocked user attempted login: {username}")
            return jsonify({"message": "User is blocked"}), 403
        
        if not check_password_hash(user.password, password):
            user.total_failures += 1
            if user.total_failures > 5:
                user.blocked = True
            db.session.commit()
            app.logger.warning(f"Failed login attempt for user: {username}")
            return jsonify({"message": "Invalid username or password"}), 401
        
        user.total_logins += 1
        if user.total_logins > 10:
            app.logger.info(f"User {username} required to change password")
            return jsonify({"message": "Password change required"}), 403
        
        db.session.commit()
        app.logger.info(f"User {username} logged in successfully")
        return jsonify({"message": "Login successful"}), 200
    except Exception as e:
        app.logger.error(f"Error logging in user: {e}")
        return jsonify({"message": "Internal server error"}), 500

@app.route('/trocasenha', methods=['PUT'])
def change_password():
    """
    Troca de Senha
    ---
    parameters:
      - name: username
        in: body
        type: string
        required: true
        description: Nome do usuário
      - name: current_password
        in: body
        type: string
        required: true
        description: Senha atual do usuário
      - name: new_password
        in: body
        type: string
        required: true
        description: Nova senha do usuário
    responses:
      200:
        description: Senha trocada com sucesso
      401:
        description: Nome de usuário ou senha inválidos
    """
    try:
        data = request.get_json()
        username = data.get('username')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, current_password):
            return jsonify({"message": "Invalid username or password"}), 401
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.total_logins = 0
        db.session.commit()
        send_email("Password Changed", user.username, "Your password has been changed successfully.")
        return jsonify({"message": "Password changed successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error changing password: {e}")
        return jsonify({"message": "Internal server error"}), 500

@app.route('/bloqueados', methods=['GET'])
def get_blocked_users():
    """
    Listar Usuários Bloqueados
    ---
    responses:
      200:
        description: Lista de usuários bloqueados
        schema:
          type: array
          items:
            properties:
              username:
                type: string
              total_failures:
                type: integer
    """
    try:
        blocked_users = User.query.filter_by(blocked=True).all()
        result = []
        for user in blocked_users:
            user_data = {'username': user.username, 'total_failures': user.total_failures}
            result.append(user_data)
        return jsonify(result), 200
    except Exception as e:
        app.logger.error(f"Error fetching blocked users: {e}")
        return jsonify({"message": "Internal server error"}), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """
    Estatísticas de Usuários
    ---
    responses:
      200:
        description: Estatísticas de usuários
        schema:
          type: object
          properties:
            total_users:
              type: integer
            total_logins:
              type: integer
            total_failures:
              type: integer
    """
    try:
        total_users = User.query.count()
        total_logins = db.session.query(db.func.sum(User.total_logins)).scalar()
        total_failures = db.session.query(db.func.sum(User.total_failures)).scalar()
        stats = {
            "total_users": total_users,
            "total_logins": total_logins,
            "total_failures": total_failures
        }
        return jsonify(stats), 200
    except Exception as e:
        app.logger.error(f"Error fetching stats: {e}")
        return jsonify({"message": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
