from flask import Flask, request, jsonify,Blueprint,make_response
from flask_jwt_extended import JWTManager,jwt_required, create_access_token,get_jwt_identity,create_refresh_token,verify_jwt_in_request
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
import os
from models import db, User,Product,Store,PaymentStatus,Payment,Request
from flask_restful import Api, Resource
from flask_migrate import Migrate
from flask_cors import CORS,cross_origin
import models
from flask.views import MethodView
from datetime import timedelta
import secrets
import string
from datetime import datetime
from werkzeug.security import generate_password_hash
from flask_restful import Resource, Api, reqparse
import json
import logging




profile_bp = Blueprint('profile', __name__)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myduka.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  # Change this to a secure secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=120) 
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Change this to your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
INVITE_REGISTER_TOKEN = os.environ.get('INVITE_REGISTER_TOKEN')

# Initialize Flask extensions
models.db.init_app(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
api = Api(app)
migrate = Migrate(app, db)
# Configure CORS
CORS(app, resources={r"/*": {
    "origins": "*",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "allow_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True
}})

logging.basicConfig(level=logging.DEBUG)

@app.route('/api/data', methods=["GET", "POST", "PUT", "DELETE"])
def handle_data():
    return 'This is some data from the API.'


#######################################DAVE ROUTE FOR HOME DEFAULT ROUTE (WORKS )AND GENERATING SECURITY PASSWORD##############################################################################################

@app.route('/', methods=['GET'])
def home():
    return "Welcome to my Duka Backend"


def generate_secure_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

#######################################ROUTE FOR LOGIN (WORKS) FOR EVERYBODY ALL USERS########################################################################################################
def create_jwt_token(user):
    additional_claims = {
        'id': user.id,
        'role': user.role
    }
    access_token = create_access_token(identity=user.email, additional_claims=additional_claims)
    return access_token

def create_token_for_user(user):
    identity = {
        'id': user.id,
        'role': user.role,
        'store_id': user.store_id  # Ensure store_id is a valid attribute of the user
    }
    access_token = create_access_token(identity=identity)
    return access_token


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

        # Assuming you have a method to check the password
        # if not user.check_password(password):
        #     return {"error": "Incorrect password"}, 401

        access_token = create_token_for_user(user)
        refresh_token = create_refresh_token(identity={'id': user.id, 'role': user.role, 'email': user.email})
        return {"access_token": access_token, "refresh_token": refresh_token}, 200

api.add_resource(Login, '/login')

#################### ROUTE FOR TokenRefresh (WORKS) IS FOR EVERYONE #################################################################################################### 
class TokenRefresh(Resource):
    @cross_origin() 
    @jwt_required(refresh=True)
    def post(self):
        try:
            current_user = get_jwt_identity()
            access_token = create_access_token(identity=current_user)
            return {'access_token': access_token}, 200
        except Exception as e:
            return jsonify(error=str(e)), 500

api.add_resource(TokenRefresh, '/refresh-token')

#######################################ROUTE FOR MANAGING ADMINS ---------WORKS--------------##############################################################################################
class AdminManagement(Resource):
    @jwt_required()
    @cross_origin()
    def post(self):
        data = request.json
        email = data.get('email')
        store_id = data.get('store_id')

        current_user = get_jwt_identity()
        if current_user['role'] != 'merchant':
            return jsonify({'error': 'Unauthorized'}), 401

        store = Store.query.get(store_id)
        if not store:
            return jsonify({'error': 'Store not found'}), 404
        
        registration_link = f"http://myduka.com/store/{store_id}/register-admin?token={INVITE_REGISTER_TOKEN}"

        msg = Message('Admin Registration Link', sender='MyDukaMerchant@gmail.com', recipients=[email])
        msg.body = f"Use the following link to register as an admin for {store.name}: {registration_link}"
        mail.send(msg)

        return jsonify({'message': f'Registration link sent successfully for {store.name}'}), 200


    @jwt_required()
    @cross_origin()
    def get(self):
        current_user = get_jwt_identity()
        if current_user['role'] != 'merchant':
            return jsonify({'error': 'Unauthorized'}), 401

        admins = User.query.filter_by(role='admin').all()
        admins_data = [{'id': admin.id, 'name': admin.name, 'username': admin.username, 'email': admin.email, 'image': admin.image} for admin in admins]

        return jsonify({'admins': admins_data}), 200

    @jwt_required()
    @cross_origin()
    def delete(self, admin_id):
        current_user = get_jwt_identity()
        if current_user['role'] != 'merchant':
            return jsonify({'error': 'Unauthorized'}), 401

        admin = User.query.get(admin_id)
        if not admin or admin.role != 'admin':
            return jsonify({'error': 'Admin not found'}), 404

        try:
            db.session.delete(admin)
            db.session.commit()
            return jsonify({'message': 'Admin deleted successfully'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

class AdminActivation(Resource):
    @jwt_required()
    @cross_origin()
    def patch(self, id, action):
        current_user_identity = get_jwt_identity()

        if not isinstance(current_user_identity, dict) or 'role' not in current_user_identity:
            return jsonify({'error': 'Invalid token structure'}), 400

        current_user_role = current_user_identity['role']

        if current_user_role != 'merchant':
            return jsonify({'error': 'Unauthorized'}), 401

        admin = User.query.get(id)
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404

        try:
            if action == 'deactivate':
                admin.active = False
            elif action == 'reactivate':
                admin.active = True
            else:
                return jsonify({'error': 'Invalid action'}), 400

            db.session.commit()
            return jsonify({'message': f'Admin account {action}d successfully'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.before_request
def check_if_user_is_active():
    if request.endpoint not in ('login', 'register', 'static'):
        try:
            verify_jwt_in_request()
            current_user_identity = get_jwt_identity()
            if isinstance(current_user_identity, dict) and 'email' in current_user_identity:
                user = User.query.filter_by(email=current_user_identity['email']).first()
                if user and not user.active:
                    return jsonify({'error': 'User account is deactivated'}), 401
        except Exception as e:
            pass

api.add_resource(AdminManagement, '/invite-admin', '/admins', '/admin/<int:admin_id>')
api.add_resource(AdminActivation, '/admin/<int:id>/<string:action>')

class RegisterAdmin(Resource):
    @cross_origin()
    def post(self, store_id):
        token = request.args.get('token')
        data = request.json

        if not data:
            return jsonify({'error': 'No input data provided'}), 400

        name = data.get('name')
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        image = data.get('image')
        role = 'admin'

        if not all([name, email, username, password]):
            return jsonify({'error': 'Missing required fields'}), 400

        try:
            if token == INVITE_REGISTER_TOKEN:
                if User.query.filter_by(email=email).first():
                    return jsonify({'error': 'User already exists'}), 400

                new_admin = User(
                    name=name,
                    email=email,
                    username=username,
                    password=password,
                    image=image,
                    role=role,
                    store_id=store_id
                )
                db.session.add(new_admin)
                db.session.commit()

                return jsonify({'message': 'Admin registered successfully'}), 201
            else:
                return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'error': str(e)}), 500

# Add this resource to your API
api.add_resource(RegisterAdmin, '/store/<int:store_id>/register')

####################################################################################################################################################################
# AdminManagement is a class that inherits from flask_restful.Resource.
# The post method handles inviting an admin (POST /invite-admin).
# The put method handles registering an admin using the tokenized link (PUT /store/<int:store_id>/register-admin).
# The get method retrieves all admins (GET /admins).
# The patch method handles deactivating and reactivating an admin (PATCH /admin/<int:id>/<string:action>).
# The check_if_user_is_active function checks if the user is active before processing other requests.
# The routes are added using api.add_resource, linking the endpoints to the AdminManagement resource.
#######################################ROUTES FOR CLERK-MANAGEMENT ---------TO BE TESTED-------(ADMIN ONLY)##############################################################################################

class ClerkManagement(Resource):
    @jwt_required()
    @cross_origin()
    
    def post(self, store_id):
        current_user = get_jwt_identity()
        if current_user['role'] != 'admin':
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.json
        name = data.get('name')
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        image = data.get('image')
        role = 'clerk'

        if not name or not username or not email or not image or not password:
            return jsonify({'error': 'Missing required fields'}), 400

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({'error': 'Username or email already exists'}), 400

        # Create a new User instance and set the password attribute
        new_clerk = User(name=name, email=email, username=username, password=password, image=image, role=role, store_id=store_id)
        new_clerk.password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash the password
        db.session.add(new_clerk)
        db.session.commit()

        return jsonify({'message': 'Clerk registered successfully'}), 201

    @jwt_required()
    @cross_origin()
    def get(self, store_id):
        current_user = get_jwt_identity()
        logging.debug(f"Current user: {current_user}")

        if current_user['role'] not in ['admin', 'merchant']:
            return jsonify({'error': 'Unauthorized'}), 401

        clerks = User.query.filter_by(store_id=store_id, role='clerk').all()
        logging.debug(f"Clerks found: {clerks}")

        serialized_clerks = [clerk.serialize() for clerk in clerks]
        logging.debug(f"Serialized clerks: {serialized_clerks}")

        return jsonify(serialized_clerks), 200

    @jwt_required()
    @cross_origin() 
    def delete(self, store_id, clerk_id):
        current_user = get_jwt_identity()
        if current_user['role'] != 'admin':
            return jsonify({'error': 'Unauthorized'}), 401

        clerk = User.query.filter_by(id=clerk_id, store_id=store_id, role='clerk').first()
        if clerk:
            db.session.delete(clerk)
            db.session.commit()
            return jsonify({'message': 'Clerk deleted successfully'}), 200
        else:
            return jsonify({'error': 'Clerk not found'}), 404

# Add the ClerkManagement resource to the API
api.add_resource(ClerkManagement,
                 '/store/<int:store_id>/clerks',
                 '/store/<int:store_id>/clerk/<int:clerk_id>')


# ###################################ClerkManagement is a class that inherits from flask_restful.Resource.#################################################
# The post method handles clerk registration (POST /store/<int:store_id>/register-clerk).
# The get method retrieves all clerks for a given store (GET /store/<int:store_id>/clerks).
# The delete method deletes a specific clerk (DELETE /store/<int:store_id>/clerk/<int:clerk_id>).
# The routes are added using api.add_resource, linking the endpoints to the ClerkManagement resource.
####################################### ROUTES FOR STORES (MERCHANT ONLY) --------WORKS-------##############################################################################################


logging.basicConfig(level=logging.DEBUG)

class Stores(Resource):
    @jwt_required()
    @cross_origin()
    def get(self):
        try:
            current_user = get_jwt_identity()
            logging.debug(f"Current user: {current_user}")

            if current_user['role'] != 'merchant':
                return make_response(jsonify({'error': 'Unauthorized'}), 401)

            merchant = User.query.filter_by(id=5, role='merchant').first()
            if not merchant:
                return make_response(jsonify({'error': 'Merchant not found'}), 404)

            # Access the stores related to the merchant
            stores = Store.query.filter_by(user_id=5).all()
            stores_list = [{'id': store.id, 'name': store.name, 'location': store.location} for store in stores]

            return make_response(jsonify({'stores': stores_list}), 200)
        except Exception as e:
            logging.error(f"Error: {e}")
            return make_response(jsonify({'error': str(e)}), 500)

    @jwt_required()
    @cross_origin()
    def post(self):
        current_user = get_jwt_identity()
        if current_user['role'] != 'merchant':
            return make_response(jsonify({'error': 'Unauthorized'}), 401)

        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('image', type=str, required=True)
        parser.add_argument('location', type=str, required=True)
        args = parser.parse_args()

        new_store = Store(name=args['name'], image=args['image'], location=args['location'], user_id=5)  # user_id is always 5
        db.session.add(new_store)
        db.session.commit()

        return make_response(jsonify({'message': 'Store created successfully'}), 201)

    @jwt_required()
    @cross_origin()
    def delete(self, store_id):
        current_user = get_jwt_identity()
        if current_user['role'] != 'merchant':
            return make_response(jsonify({'error': 'Unauthorized'}), 401)

        store = Store.query.filter_by(id=store_id, user_id=5).first()  # user_id is always 5
        if not store:
            return make_response(jsonify({'error': 'Store not found'}), 404)

        db.session.delete(store)
        db.session.commit()

        return make_response(jsonify({'message': 'Store deleted successfully'}), 200)

api.add_resource(Stores, '/stores', '/stores/<int:store_id>')

# Error handling for better debug information
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error
    app.logger.error(f'Error: {e}')
    # Return a JSON response with the error message
    return make_response(jsonify({'error': str(e)}), 500)


####################################### ROUTE FOR GETTING STORE AND PRODUCTPERFORMANCE (MERCHANT ONLY)------WORKS--------##############################################################################################
class Performance(Resource):
    @jwt_required()
    @cross_origin()
    def get(self, store_id, performance_type):
        current_user = get_jwt_identity()
        if current_user['role'] != 'merchant':
            return jsonify({'error': 'Unauthorized'}), 401

        store = Store.query.get(store_id)
        if not store:
            return jsonify({'error': 'Store not found'}), 404

        if performance_type == 'store':
            return self.get_store_performance(store)
        elif performance_type == 'product':
            return self.get_product_performance(store)
        else:
            return jsonify({'error': 'Invalid performance type'}), 400

    def get_store_performance(self, store):
        total_revenue = store.calculate_total_revenue()
        total_profit = store.calculate_total_profit()

        store_performance = {
            'store_id': store.id,
            'store_name': store.name,
            'total_revenue': total_revenue,
            'total_profit': total_profit
        }

        return jsonify(store_performance), 200

    def get_product_performance(self, store):
        product_performance = []
        for product in store.products:
            performance_data = {
                'product_id': product.id,
                'product_name': product.name,
                'revenue': product.calculate_revenue(),
                'profit': product.calculate_profit()
            }
            product_performance.append(performance_data)

        return jsonify(product_performance), 200

# Adding the routes to the API
api.add_resource(Performance, '/store/<int:store_id>/performance/<string:performance_type>')


################HOW TO USE THIS PERFORMANCE CLASS FOR GETTING STORE PERFORMANCE(GET /store/1/performance/store)##### FOR GETTING PRODUCT PERFORMANCE (GET /store/1/product)#########

###########################################ROUTE FOR GETTING REQUEST#####################################################################################################################

class Requests(Resource):
    @jwt_required()
    @cross_origin()
    def get(self, store_id):
        current_user = get_jwt_identity()

        if current_user['role'] not in ['admin', 'clerk']:
            return jsonify({'error': 'Unauthorized'}), 401

        store = Store.query.get(store_id)
        if not store:
            return jsonify({'error': 'Store not found'}), 404

        requests = Request.query.filter_by(store_id=store_id).all()
        serialized_requests = [
            {
                'id': request.id,
                'store_id': request.store_id,
                'product_name': request.product_name,
                'quantity': request.quantity,
                'requester_name': request.requester_name,
                'requester_contact': request.requester_contact,
                'status': request.status
            } for request in requests
        ]

        return jsonify({'requests': serialized_requests}), 200
    
    @jwt_required()
    @cross_origin()
    def post(self, store_id):
        current_user = get_jwt_identity()

        if current_user['role'] != 'clerk':
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.json
        product_name = data.get('product_name')
        quantity = data.get('quantity')
        requester_name = data.get('requester_name')
        requester_contact = data.get('requester_contact')
        status = data.get('status', 'pending')

        if not (product_name and quantity and requester_name and requester_contact):
            return jsonify({'error': 'Missing required fields'}), 400

        existing_request = Request.query.filter_by(
            store_id=store_id,
            product_name=product_name,
            quantity=quantity,
            requester_name=requester_name,
            requester_contact=requester_contact,
            status='pending'
        ).first()

        if existing_request:
            return jsonify({'message': 'The request has already been sent'}), 409

        new_request = Request(
            store_id=store_id,
            product_name=product_name,
            quantity=quantity,
            requester_name=requester_name,
            requester_contact=requester_contact,
            status=status
        )
        db.session.add(new_request)
        db.session.commit()

        return jsonify({'message': 'Request added successfully'}), 201

class RequestManagement(Resource):
    @jwt_required()
    @cross_origin()
    def delete(self, store_id, request_id):
        current_user = get_jwt_identity()

        if current_user['role'] in ['admin', 'clerk']:
            request_item = Request.query.filter_by(id=request_id, store_id=store_id).first()

            if request_item:
                db.session.delete(request_item)
                db.session.commit()
                return jsonify({'message': 'Request deleted successfully'}), 200
            else:
                return jsonify({'error': 'Request not found'}), 404
        else:
            return jsonify({'error': 'Unauthorized'}), 401

    @jwt_required()
    @cross_origin()
    def put(self, store_id, request_id):
        current_user = get_jwt_identity()

        if current_user['role'] in ['admin',]:
            status = request.json.get('status')

            if status and status in ['Approved', 'Disapproved']:
                request_item = Request.query.filter_by(id=request_id, store_id=store_id).first()

                if request_item:
                    request_item.status = status
                    db.session.commit()
                    return jsonify({'message': f'Request status updated to {status}'}), 200
                else:
                    return jsonify({'error': 'Request not found'}), 404
            else:
                return jsonify({'error': 'Invalid status provided'}), 400
        else:
            return jsonify({'error': 'Unauthorized'}), 401

# Register the resource and specify the routes
api.add_resource(Requests, '/store/<int:store_id>/requests')
api.add_resource(RequestManagement, '/store/<int:store_id>/request/<int:request_id>')

#######################################ROUTE FOR GETTING PAYMENT AND PAYMENT DETAILS PER STORE (MERCHANT AND ADMIN ONLY)-----------WORKS----------##############################################################################################
class Payments(Resource):
    @jwt_required()
    @cross_origin()
    def get(self, store_id):
        current_user = get_jwt_identity()
        logging.debug(f"Current user identity: {current_user}")

        if not isinstance(current_user, dict) or 'id' not in current_user or 'role' not in current_user:
            return jsonify({'error': 'Invalid JWT token structure'}), 400

        if current_user['role'] not in ['merchant', 'admin', 'clerk']:
            return jsonify({'error': 'Unauthorized - Role not merchant, admin, or clerk'}), 401

        store = Store.query.get(store_id)
        if not store:
            return jsonify({'error': 'Store not found'}), 404

        if current_user['role'] == 'merchant' and store.user_id != current_user['id']:
            return jsonify({'error': 'Unauthorized - Store does not belong to user'}), 401

        payments = Payment.query.filter_by(store_id=store_id).all()

        serialized_payments = []
        for payment in payments:
            serialized_payment = {
                'id': payment.id,
                'product_name': payment.product_name,
                'status': payment.status.value,
                'date': payment.date,
                'amount': payment.amount,
                'method': payment.method,
                'due_date': payment.due_date.strftime('%Y-%m-%d')
            }
            serialized_payments.append(serialized_payment)

        paid_payments = [payment for payment in serialized_payments if payment['status'] == PaymentStatus.PAID.value]
        unpaid_payments = [payment for payment in serialized_payments if payment['status'] == PaymentStatus.NOT_PAID.value]

        response_data = {
            'store_id': store_id,
            'paid_payments': paid_payments,
            'unpaid_payments': unpaid_payments
        }

        return jsonify(response_data), 200

    @jwt_required()
    @cross_origin()
    def post(self, store_id):
        current_user = get_jwt_identity()

        if not isinstance(current_user, dict) or 'id' not in current_user or 'role' not in current_user:
            return jsonify({'error': 'Invalid JWT token structure'}), 400

        if current_user['role'] != 'admin':
            return jsonify({'error': 'Unauthorized'}), 401

        store = Store.query.get(store_id)
        if not store:
            return jsonify({'error': 'Store not found'}), 404

        data = request.json
        product_name = data.get('product_name')
        status = data.get('status')
        amount = data.get('amount')
        method = data.get('method')
        due_date = data.get('due_date')

        if not product_name or not status or not amount or not method or not due_date:
            return jsonify({'error': 'Missing required fields'}), 400

        new_payment = Payment(
            store_id=store_id,
            product_name=product_name,
            amount=amount,
            method=method,
            due_date=datetime.strptime(due_date, '%Y-%m-%d').date()
        )

        db.session.add(new_payment)
        db.session.commit()

        return jsonify({'message': 'Payment created successfully'}), 201

class PaymentManagement(Resource):
    @jwt_required()
    @cross_origin()
    def delete(self, store_id, payment_id):
        current_user = get_jwt_identity()

        if not isinstance(current_user, dict) or 'id' not in current_user or 'role' not in current_user:
            return jsonify({'error': 'Invalid JWT token structure'}), 400

        if current_user['role'] != 'admin':
            return jsonify({'error': 'Unauthorized'}), 401

        store = Store.query.get(store_id)
        if not store:
            return jsonify({'error': 'Store not found'}), 404

        payment = Payment.query.get(payment_id)
        if not payment or payment.store_id != store_id:
            return jsonify({'error': 'Payment not found'}), 404

        db.session.delete(payment)
        db.session.commit()

        return jsonify({'message': 'Payment deleted successfully'}), 200

# Register the resource and specify the routes
api.add_resource(Payments, '/store/<int:store_id>/payments')
api.add_resource(PaymentManagement, '/store/<int:store_id>/payments/<int:payment_id>')



#######################################ROUTE FOR PRODUCTS----------WORKS-------------##############################################################################################
class Products(Resource):
    @jwt_required()
    @cross_origin()
    def get(self, id):
        current_user = get_jwt_identity()

        if current_user['role'] in ['merchant', 'admin', 'clerk']:
            products = Product.query.filter_by(store_id=id).all()
            serialized_products = [product.serialize() for product in products]
            return jsonify(serialized_products), 200
        else:
            return jsonify({"message": "Unauthorized"}), 401
    
    @jwt_required()
    @cross_origin()
    def post(self, id):
        current_user = get_jwt_identity()

        if current_user['role'] == 'clerk':
            data = request.json
            name = data.get('name')
            image = data.get('image')
            price = data.get('price')
            condition = data.get('condition')
            stock_quantity = data.get('stock_quantity')
            spoil_quantity = data.get('spoil_quantity')
            buying_price = data.get('buying_price')
            selling_price = data.get('selling_price')
            sales = data.get('sales')
            sales_date_str = data.get('sales_date')

            if not (name and price and condition and stock_quantity and buying_price and selling_price):
                return jsonify({'error': 'Missing required fields'}), 400

            sales_date = datetime.strptime(sales_date_str, '%Y-%m-%dT%H:%M:%S')
            store_id = id

            existing_product = Product.query.filter_by(store_id=store_id, name=name).first()

            if existing_product:
                return jsonify({'message': 'The product already exists'}), 409
            else:
                new_product = Product(
                    name=name,
                    image=image,
                    price=price,
                    condition=condition,
                    stock_quantity=stock_quantity,
                    spoil_quantity=spoil_quantity,
                    buying_price=buying_price,
                    selling_price=selling_price,
                    sales=sales,
                    sales_date=sales_date,
                    store_id=store_id
                )
                db.session.add(new_product)
                db.session.commit()

                product_info = {
                    'id': new_product.id,
                    'name': new_product.name,
                    'image': new_product.image,
                    'price': new_product.price,
                    'condition': new_product.condition,
                    'stock_quantity': new_product.stock_quantity,
                    'spoil_quantity': new_product.spoil_quantity,
                    'buying_price': new_product.buying_price,
                    'selling_price': new_product.selling_price,
                    'sales': new_product.sales,
                    'sales_date': new_product.sales_date.isoformat(),
                    'store_id': new_product.store_id
                }

                return jsonify({'message': 'Product added successfully', 'product': product_info}), 201
        else:
            return jsonify({"message": "Unauthorized"}), 401
        
    @jwt_required()
    @cross_origin()
    def delete(self, id, product_id):
        current_user = get_jwt_identity()

        if current_user['role'] == 'clerk':
            product = Product.query.filter_by(id=product_id, store_id=id).first()

            if product:
                db.session.delete(product)
                db.session.commit()
                return jsonify({'message': 'Product deleted successfully'}), 200
            else:
                return jsonify({'error': 'Product not found'}), 404
        else:
            return jsonify({"message": "Unauthorized"}), 401

# Register the resource and specify the routes
api.add_resource(Products, '/store/<int:id>/products', '/store/<int:id>/products/<int:product_id>')


if __name__ == '__main__':
    app.run(debug=True, port = 5000)
    
