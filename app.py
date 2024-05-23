from flask import Flask, request, jsonify, Blueprint
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_restful import Api, Resource
from flask_migrate import Migrate
from flask_cors import CORS
from datetime import timedelta
import os
import secrets
import string
from models import db, User

# Initialize Flask app
app = Flask(__name__)

# App configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myduka.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  # Ensure this is set in your environment variables
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30) 
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Configure your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
INVITE_REGISTER_TOKEN = os.getenv('INVITE_REGISTER_TOKEN')

# Initialize Flask extensions
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
api = Api(app)
migrate = Migrate(app, db)
CORS(app)
CORS(app, origins=['http://localhost:5173','flick-fusion-frontend.vercel.app'])
# Blueprint for profile (if needed)
profile_bp = Blueprint('profile', __name__)

# Route to ensure the server is running
@app.route('/', methods=['GET'])
def home():
    return "Welcome to my Duka Backend"

# Function to generate a secure password
def generate_secure_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

# Login route
class Login(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400

        email = data.get('email')
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return {"error": "User does not exist"}, 401

        if not bcrypt.check_password_hash(user.password, password):
            return {"error": "Incorrect password"}, 401

        access_token = create_access_token(identity={'email': user.email, 'role': user.role})
        refresh_token = create_refresh_token(identity={'email': user.email, 'role': user.role})
        return {"access_token": access_token, "refresh_token": refresh_token}, 200

# Token refresh route
class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        try:
            current_user = get_jwt_identity()
            access_token = create_access_token(identity=current_user)
            return {'access_token': access_token}, 200
        except Exception as e:
            return jsonify(error=str(e)), 500

# Add resources to API
api.add_resource(Login, '/login')
api.add_resource(TokenRefresh, '/refresh-token')


