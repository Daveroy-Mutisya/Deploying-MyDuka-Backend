from flask import Flask, request, jsonify,Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager,jwt_required, create_access_token,get_jwt_identity,create_refresh_token,verify_jwt_in_request
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
import os
from models import db, User,Product,Store,PaymentStatus,Payment,Request
from flask_restful import Api, Resource
from flask_migrate import Migrate
from flask_cors import CORS
import models
from flask.views import MethodView
from datetime import timedelta
import secrets
import string
from datetime import datetime
from werkzeug.security import generate_password_hash


profile_bp = Blueprint('profile', __name__)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myduka.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  # Change this to a secure secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30) 
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Change this to your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
INVITE_REGISTER_TOKEN = os.environ.get('INVITE_REGISTER_TOKEN')

# Initialize Flask extensions
models.db.init_app(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
api = Api(app)
migrate = Migrate(app, db)

#######################################DAVE ROUTE FOR HOME DEFAULT ROUTE (WORKS )AND GENERATING SECURITY PASSWORD##############################################################################################

@app.route('/', methods=['GET'])
def home():
    return "Welcome to my Duka Backend"


def generate_secure_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

#######################################ROUTE FOR LOGIN (WORKS) FOR EVERYBODY ALL USERS########################################################################################################
def create_token_for_user(user):
    identity = {
        'id': user.id,
        'role': user.role,
        'store_id': user.store_id
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

        if not bcrypt.check_password_hash(user.password, password):
            return {"error": "Incorrect password"}, 401

        access_token = create_access_token(identity={'email': user.email, 'role': user.role})
        refresh_token = create_refresh_token(identity={'email': user.email, 'role': user.role})
        return {"access_token": access_token, "refresh_token": refresh_token}, 200

api.add_resource(Login, '/login')


#################### ROUTE FOR TokenRefresh (WORKS) IS FOR EVERYONE #################################################################################################### 
class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        try:
            current_user = get_jwt_identity()
            access_token = create_access_token(identity=current_user)
            return {'access_token': access_token}, 200
        except Exception as e:
            return jsonify(error=str(e)), 500

api.add_resource(TokenRefresh, '/refresh-token')

###############################################PROFILE ROUTE ---------WORKS-------------- (FOR ALL USERS)#########################################################################################
class Profile:
    @staticmethod
    @profile_bp.route('/profile', methods=['GET'])
    @jwt_required()
    def get_profile():
        current_user = get_jwt_identity()
        user = User.query.filter_by(id=current_user['id']).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        user_data = {
            'id': user.id,
            'name': user.name,
            'username': user.username,
            'email': user.email,
            'image': user.image,
            'role': user.role,
            'entries': user.entries,
            'active': user.active
        }
        return jsonify(user_data), 200

    @staticmethod
    @profile_bp.route('/profile', methods=['PATCH'])
    @jwt_required()
    def update_profile():
        current_user = get_jwt_identity()
        user = User.query.filter_by(id=current_user['id']).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.json

        if 'name' in data:
            user.name = data['name']
        if 'username' in data:
            if User.query.filter_by(username=data['username']).first() and user.username != data['username']:
                return jsonify({'error': 'Username already taken'}), 409
            user.username = data['username']
        if 'email' in data:
            if User.query.filter_by(email=data['email']).first() and user.email != data['email']:
                return jsonify({'error': 'Email already taken'}), 409
            user.email = data['email']
        if 'password' in data:
            user.password = generate_password_hash(data['password'])
        if 'image' in data:
            user.image = data['image']

        db.session.commit()

        updated_user_data = {
            'id': user.id,
            'name': user.name,
            'username': user.username,
            'email': user.email,
            'image': user.image,
            'role': user.role,
            'entries': user.entries,
            'active': user.active
        }

        return jsonify({'message': 'Profile updated successfully', 'user': updated_user_data}), 200

# Register the blueprint with your Flask app
app.register_blueprint(profile_bp)

#######################################DAVE ROUTE FOR SENDING ADMINS INVITES THROUGH EMAILS(MERCHANT ONLY) ---------WORKS--------------##############################################################################################

@app.route('/invite-admin', methods=['POST'])
def invite_admin():
    data = request.json
    email = data.get('email')
    store_id = data.get('store_id')  # Add store ID to the request data

    # Check if the email belongs to the merchant (superuser)
    if email != 'myduka7@gmail.com':  # Change this to your superuser email
        return jsonify({'error': 'Unauthorized'}), 401

    # Check if the store exists
    store = Store.query.get(store_id)
    if not store:
        return jsonify({'error': 'Store not found'}), 404

    # Generate access token for registration link
    access_token = create_access_token(identity=email)

    # Construct the registration link with token and store ID
    registration_link = f"http://myduka.com/store/{store_id}/register-admin?token={INVITE_REGISTER_TOKEN}"

    # Send email with tokenized link for registration
    msg = Message('Admin Registration Link', sender='MyDukaMerchant@gmail.com', recipients=[email])
    msg.body = f"Use the following link to register as an admin for {store.name}: {registration_link}"
    mail.send(msg)

    return jsonify({'message': f'Registration link sent successfully for {store.name}'}), 200


#######################################################################################################################################################################

#######################################DAVE ROUTE FOR CREATING ADMINS(MERCHANT ONLY) ---------WORKS------##############################################################################################
# Route for registering admins using the tokenized link
@app.route('/store/<int:id>/register-admin', methods=['POST'])
def register_admin():
    token = request.args.get('token')
    data = request.json
    name = data.get('name')
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    image = data.get('image')  # Adding image field
    role = 'admin'

    # Verify token
    try:
        if token == INVITE_REGISTER_TOKEN:
            # Check if user already exists
            if User.query.filter_by(email=email).first():
                return jsonify({'error': 'User already exists'}), 400

            # Create new user
            new_admin = User(name= name,email=email, username=username, password=password, image=image, role=role)

            db.session.add(new_admin)
            db.session.commit()

            return jsonify({'message': 'Admin registered successfully'}), 201
        else:
            return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

###################################################################################################################################################################

#######################################DAVE ROUTE FOR GETTING ADMINS ---------WORKS-------(MERCHANT ONLY)##############################################################################################

@app.route('/admins', methods=['GET'])
@jwt_required()  # Requires authentication
def get_admins():
    current_user = get_jwt_identity()
    if current_user['role'] != 'merchant':
        return jsonify({'error': 'Unauthorized'}), 401

    # Retrieve all admin users
    admins = User.query.filter_by(role='admin').all()

    # Serialize the data (convert to JSON format)
    admins_data = [{'id': admin.id, 'name': admin.name, 'username': admin.username, 'email': admin.email} for admin in admins]

    return jsonify({'admins': admins_data}), 200

#############################################################################################################################################################

####################################### DAVE ROUTE FOR DEACTIVATION AND REACTIVATION OF ADMINS MERCHANT ONLY(WORKS)##############################################################################################


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
            pass  # Handle token verification exceptions if necessary
         


@app.route('/admin/<int:id>/deactivate', methods=['PATCH'])
@jwt_required()  # Requires authentication
def deactivate_admin(id):
    current_user_identity = get_jwt_identity()
    
    # Check if the required keys exist in the identity
    if not isinstance(current_user_identity, dict) or 'role' not in current_user_identity:
        return jsonify({'error': 'Invalid token structure'}), 400

    current_user_role = current_user_identity['role']  # Extract the role from the identity

    if current_user_role != 'merchant':
        return jsonify({'error': 'Unauthorized'}), 401

    admin = User.query.get(id)
    if not admin:
        return jsonify({'error': 'Admin not found'}), 404

    try:
        admin.active = False
        db.session.commit()
        return jsonify({'message': 'Admin account deactivated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/<int:id>/reactivate', methods=['PATCH'])
@jwt_required()  # Requires authentication
def reactivate_admin(id):
    current_user_identity = get_jwt_identity()

    if not isinstance(current_user_identity, dict) or 'role' not in current_user_identity:
        return jsonify({'error': 'Invalid token structure'}), 400

    current_user_role = current_user_identity['role']  # Extract the role from the identity

    if current_user_role != 'merchant':
        return jsonify({'error': 'Unauthorized'}), 401

    admin = User.query.get(id)
    if not admin:
        return jsonify({'error': 'Admin not found'}), 404

    try:
        admin.active = True
        db.session.commit()
        return jsonify({'message': 'Admin account reactivated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


#######################################ROUTE FOR CREATING CLERKS ---------WORKS-------(ADMIN ONLY)##############################################################################################

@app.route('/store/<int:store_id>/register-clerk', methods=['POST'])
@jwt_required()  # Requires authentication
def register_clerk():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    name = data.get('name')
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    image = data.get('image')  # Adding image field
    role = 'clerk'

    if not name or not username or not email or not image or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    # Check if the username or email already exists
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({'error': 'Username or email already exists'}), 400

    # Create a new clerk user
    new_clerk = User(name=name, username=username, email=email, password=password, role=role, image=image)

    # Add the new clerk to the database
    db.session.add(new_clerk)
    db.session.commit()

    return jsonify({'message': 'Clerk registered successfully'}), 201

# Assuming you have a relationship defined between Store and Merchant

####################################### ROUTES FOR STORES (MERCHANT ONLY) --------WORKS-------##############################################################################################

@app.route('/stores/', methods=['GET'])
@jwt_required()  # Requires authentication
def get_stores():
    current_user = get_jwt_identity()
    if current_user['role'] != 'merchant':
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Assuming the Merchant model has a stores relationship
    merchant = User.query.filter_by(id=current_user['id']).first()
    if not merchant:
        return jsonify({'error': 'Merchant not found'}), 404
    
    stores = merchant.stores
    
    # Convert stores to a list of dictionaries
    stores_list = []
    for store in stores:
        store_data = {
            'id': store.id,
            'name': store.name,
            'location': store.location,
            # Add more fields as needed
        }
        stores_list.append(store_data)
    
    return jsonify({'stores': stores_list}), 200

####################################ROUTE FOR CREATING A STORE(MERCHANT ONLY)######################################---------WORKS--------------#####################################################
# Add store (POST)
@app.route('/stores', methods=['POST'])
@jwt_required()
def create_store():
    current_user = get_jwt_identity()
    if current_user['role'] != 'merchant':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    name = data.get('name')
    image = data.get('image')
    location = data.get('location')
    if not name or not image or not location:
        return jsonify({'error': 'Missing required fields'}), 400
    
    new_store = Store(name=name, image=image, location=location, user_id=current_user['id'])
    db.session.add(new_store)
    db.session.commit()

    return jsonify({'message': 'Store created successfully'}), 201

###############################################ROUTE FOR EDITING A STORE(MERCHANT ONLY)###################---------WORKS--------------##############################################################################
# Edit store (PATCH)
@app.route('/stores/<int:store_id>', methods=['PATCH'])
@jwt_required()
def edit_store(store_id):
    current_user = get_jwt_identity()
    store = Store.query.filter_by(id=store_id, user_id=current_user['id']).first()
    if not store:
        return jsonify({'error': 'Store not found'}), 404
    
    data = request.json
    name = data.get('name')
    image = data.get('image')
    location = data.get('location')
    if not name or not image or not location:
        return jsonify({'error': 'Missing required fields'}), 400
    
    store.name = name
    store.image = image
    store.location = location
    db.session.commit()

    return jsonify({'message': 'Store updated successfully'}), 200

########################################ROUTE FOR DELETING A STORE (MERCHANT ONLY)############################################---------(WORKS)--------------###############################
# Delete store (DELETE)
@app.route('/stores/<int:store_id>', methods=['DELETE'])
@jwt_required()
def delete_store(store_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'merchant':
        return jsonify({'error': 'Unauthorized'}), 401
    
    store = Store.query.filter_by(id=store_id, user_id=current_user['id']).first()
    if not store:
        return jsonify({'error': 'Store not found'}), 404
    
    db.session.delete(store)
    db.session.commit()

    return jsonify({'message': 'Store deleted successfully'}), 200


####################################### ROUTE FOR GETTING STORE-PERFORMANCE (MERCHANT ONLY)------WORKS--------##############################################################################################
# Route for retrieving individual store performance (merchant only)
@app.route('/store/<int:store_id>/performance', methods=['GET'])
@jwt_required()  # Requires authentication
def get_store_performance(store_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'merchant':
        return jsonify({'error': 'Unauthorized'}), 401

    store = Store.query.get(store_id)
    if not store:
        return jsonify({'error': 'Store not found'}), 404

    total_revenue = store.calculate_total_revenue()
    total_profit = store.calculate_total_profit()

    store_performance = {
        'store_id': store.id,
        'store_name': store.name,
        'total_revenue': total_revenue,
        'total_profit': total_profit
    }

    return jsonify(store_performance), 200

####################################### ROUTE FOR GETTING HOW PRODUCTS ARE PERFORMING PER STORE----------- WORKS---------(MERCHANT ONLY)##############################################################################################

# Route for retrieving individual product performance within a store (merchant only)
@app.route('/store/<int:store_id>/product-performance', methods=['GET'])
@jwt_required()  # Requires authentication
def get_product_performance(store_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'merchant':
        return jsonify({'error': 'Unauthorized'}), 401

    store = Store.query.get(store_id)
    if not store:
        return jsonify({'error': 'Store not found'}), 404

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

#######################################ROUTE FOR GETTING PAYMENT AND PAYMENT DETAILS PER STORE (MERCHANT AND ADMIN ONLY)-----------WORKS----------##############################################################################################
@app.route('/store/<int:store_id>/payments', methods=['GET'])
@jwt_required()  # Requires authentication
def get_store_payments(store_id):
    current_user = get_jwt_identity()

    # Check if the user is authenticated as a merchant
    if current_user['role'] != ['merchant','admin']:
        return jsonify({'error': 'Unauthorized - Role not merchant'}), 401

    # Query the store by ID
    store = Store.query.get(store_id)
    if not store:
        return jsonify({'error': 'Store not found'}), 404

    # Check if the store belongs to the current user (merchant)
    if store.user_id != current_user['id']:
        return jsonify({'error': 'Unauthorized - Store does not belong to user'}), 401

    # Query payments for the specified store
    payments = Payment.query.filter_by(store_id=store_id).all()

    # Serialize payments into a format suitable for the API response
    serialized_payments = []
    for payment in payments:
        serialized_payment = {
            'id': payment.id,
            'status': payment.status.value,  # Convert Enum to its value
            'date': payment.date,
            'amount': payment.amount,
            'method': payment.method,
            'due_date': payment.due_date.strftime('%Y-%m-%d')  # Format date as string
        }
        serialized_payments.append(serialized_payment)

    # Group payments into paid and unpaid categories
    paid_payments = [payment for payment in serialized_payments if payment['status'] == PaymentStatus.PAID.value]
    unpaid_payments = [payment for payment in serialized_payments if payment['status'] == PaymentStatus.NOT_PAID.value]

    # Prepare the response data
    response_data = {
        'store_id': store_id,
        'paid_payments': paid_payments,
        'unpaid_payments': unpaid_payments
    }

    return jsonify(response_data), 200
############################################## ROUTE TO CREATE A PAYMENT#####################(ADMIN ONLY)---------(WORKS)--------------######################################||||||\|||||||||||||3\\\\\\\
@app.route('/store/<int:store_id>/payments', methods=['POST'])
@jwt_required()  # Requires authentication
def create_payment(store_id):
    current_user = get_jwt_identity()
    
    # Check if the user is authenticated as a merchant or admin
    if current_user['role'] not in ['admin']:
        return jsonify({'error': 'Unauthorized'}), 401

    store = Store.query.get(store_id)
    if not store:
        return jsonify({'error': 'Store not found'}), 404

    if current_user['role'] == 'merchant' and store.user_id != current_user['id']:
        return jsonify({'error': 'Unauthorized'}), 401

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

#########################################################ROUTE FOR  EDITING A PAYMENT ############(ADMIN ONLY)---------(WORKS)--------------###################################################
@app.route('/store/<int:store_id>/payments/<int:payment_id>', methods=['PATCH'])
@jwt_required()  # Requires authentication
def edit_payment(store_id, payment_id):
    current_user = get_jwt_identity()

    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    store = Store.query.get(store_id)
    if not store:
        return jsonify({'error': 'Store not found'}), 404

    payment = Payment.query.get(payment_id)
    if not payment or payment.store_id != store_id:
        return jsonify({'error': 'Payment not found'}), 404

    data = request.json
    payment.product_name = data.get('product_name', payment.product_name)
    payment.status = PaymentStatus(data.get('status', payment.status.value))
    payment.amount = data.get('amount', payment.amount)
    payment.method = data.get('method', payment.method)
    due_date = data.get('due_date')
    if due_date:
        payment.due_date = datetime.strptime(due_date, '%Y-%m-%d').date()

    db.session.commit()

    return jsonify({'message': 'Payment updated successfully'}), 200


###############################ROUTE FOR DELETING A PAYMENT #######(ADMIN ONLY)---------(Works)--------------########################################################################
@app.route('/store/<int:store_id>/payments/<int:payment_id>', methods=['DELETE'])
@jwt_required()  # Requires authentication
def delete_payment(store_id, payment_id):
    current_user = get_jwt_identity()

    if current_user['role'] not in ['admin']:
        return jsonify({'error': 'Unauthorized'}), 401

    store = Store.query.get(store_id)
    if not store:
        return jsonify({'error': 'Store not found'}), 404

    if current_user['role'] == 'merchant' and store.user_id != current_user['id']:
        return jsonify({'error': 'Unauthorized'}), 401

    payment = Payment.query.get(payment_id)
    if not payment or payment.store_id != store_id:
        return jsonify({'error': 'Payment not found'}), 404

    db.session.delete(payment)
    db.session.commit()

    return jsonify({'message': 'Payment deleted successfully'}), 200
#######################################ROUTE FOR ALL GETTING PRODUCTS (ALL USERS)----------WORKS-------------##############################################################################################

@app.route('/store/<int:id>/products', methods=['GET'])
@jwt_required()  # Requires authentication
def get_products(id):
    current_user = get_jwt_identity()
    
    # Check if the user is authenticated as a clerk or admin
    if current_user['role'] in ['merchant', 'admin','clerk']:
        # Query all products for the specified store
        products = Product.query.filter_by(store_id=id).all()

        # Serialize products into a format suitable for the API response
        serialized_products = [product.serialize() for product in products]

        # Return the serialized products as JSON response with status code 200
        return jsonify(serialized_products), 200
    else:
        return jsonify({"message": "Unauthorized"}), 401


####################################ROUTE FOR REGISTERING PRODUCTS AS A CLERK DOES ---WORKS----(CLERK ONLY)##########################################################################

@app.route('/stores/<int:id>/register-product', methods=['POST'])
@jwt_required()
def add_product(id):
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
        sales_date_str = data.get('sales_date')  # Get sales_date as string
        
        # Convert sales_date string to datetime object
        sales_date = datetime.strptime(sales_date_str, '%Y-%m-%dT%H:%M:%S')
        
        store_id = id
        
        if not (name and price and condition and stock_quantity and buying_price and selling_price and store_id):
            return jsonify({'error': 'Missing required fields'}), 400
        
        existing_product = Product.query.filter_by(
            store_id=store_id,
            name=name
        ).first()
        
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
                'sales_date': new_product.sales_date.isoformat(),  # Convert datetime object to string
                'store_id': new_product.store_id
            }
            
            return jsonify({'message': 'Product added successfully', 'product': product_info}), 201
    else:
        return jsonify({"message": "Unauthorized"}), 401

################################################ROUTES FOR EDITING/UPDATING PRODUCTS---------(WORKS)---------------(CLERK ONLY)###############################################################################################
@app.route('/stores/<int:id>/products/<int:product_id>', methods=['PATCH'])
@jwt_required()
def update_product(id, product_id):
    current_user = get_jwt_identity()
    
    if current_user['role'] != 'clerk':
        return jsonify({"message": "Unauthorized"}), 401
    
    data = request.json
    
    product = Product.query.filter_by(id=product_id, store_id=id).first()
    
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    if 'name' in data:
        product.name = data['name']
    if 'image' in data:
        product.image = data['image']
    if 'price' in data:
        product.price = data['price']
    if 'condition' in data:
        product.condition = data['condition']
    if 'stock_quantity' in data:
        product.stock_quantity = data['stock_quantity']
    if 'spoil_quantity' in data:
        product.spoil_quantity = data['spoil_quantity']
    if 'buying_price' in data:
        product.buying_price = data['buying_price']
    if 'selling_price' in data:
        product.selling_price = data['selling_price']
    if 'sales' in data:
        product.sales = data['sales']
    if 'sales_date' in data:
        product.sales_date = datetime.strptime(data['sales_date'], '%Y-%m-%d')

    
    db.session.commit()
    
    updated_product_info = {
        'id': product.id,
        'name': product.name,
        'image': product.image,
        'price': product.price,
        'condition': product.condition,
        'stock_quantity': product.stock_quantity,
        'spoil_quantity': product.spoil_quantity,
        'buying_price': product.buying_price,
        'selling_price': product.selling_price,
        'sales': product.sales,
        'sales_date': product.sales_date.isoformat(),  # Convert datetime object to string
        'store_id': product.store_id
    }

    return jsonify({'message': 'Product updated successfully', 'product': updated_product_info}), 200

################################################################ROUTES FOR ADD/REGISTERING REQUESTS(CLERK ONLY)----------WORKS-----------######################################################################################

@app.route('/stores/<int:id>/register-request', methods=['POST'])
@jwt_required()  # Requires authentication
def add_request(id):
    current_user = get_jwt_identity()
    
    # Check if the user is authenticated as a clerk
    if current_user['role'] == 'clerk':  
        data = request.json
        
        # Extract request data from the JSON payload
        product_id = data.get('product_id')
        quantity = data.get('quantity')
        requester_name = data.get('requester_name')
        requester_contact = data.get('requester_contact')
        status = data.get('status')
        
        # Retrieve store_id associated with the authenticated user
        store_id = id
        
        # Check if all required fields are present in the request
        if not (product_id and quantity and requester_name and requester_contact and store_id and status):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check if the request already exists in the database
        existing_request = Request.query.filter_by(
            store_id=store_id,
            product_id=product_id, 
            quantity=quantity, 
            requester_name=requester_name, 
            requester_contact=requester_contact,
            status='pending'
        ).first()
        
        if existing_request:
            return jsonify({'message': 'The request has already been sent'}), 409 
        else:
            # Create a new request object and add it to the database
            new_request = Request(
                store_id=store_id,
                product_id=product_id,
                quantity=quantity,
                requester_name=requester_name,
                requester_contact=requester_contact,
                status='pending'
            )
            db.session.add(new_request)
            db.session.commit()
            
            return jsonify({'message': 'Request added successfully'}), 201
    else:
        return jsonify({"message": "Unauthorized"}), 401

###########################################ROUTE FOR EDITING/UPDATING REQUEST(CLERK AND ADMIN ONLY)---------(WORKS)---------------############################################################################################
    
@app.route('/stores/<int:store_id>/requests/<int:request_id>', methods=['PATCH'])
@jwt_required()  # Requires authentication
def update_request(store_id, request_id):
    current_user = get_jwt_identity()
    
    # Check if the user is authenticated as a clerk or admin
    if current_user['role'] not in ['clerk', 'admin']:
        return jsonify({"message": "Unauthorized"}), 401
    
    # Extract request data from the JSON payload
    data = request.json
    
    # Retrieve the request to be updated
    req = Request.query.filter_by(id=request_id, store_id=store_id).first()
    
    if not req:
        return jsonify({'error': 'Request not found'}), 404

    # Update the fields if present in the request data
    if 'product_id' in data:
        req.product_id = data['product_id']
    if 'quantity' in data:
        req.quantity = data['quantity']
    if 'requester_name' in data:
        req.requester_name = data['requester_name']
    if 'requester_contact' in data:
        req.requester_contact = data['requester_contact']
    if 'status' in data:
        req.status = data['status']
    
    # Commit the changes to the database
    db.session.commit()
    
    updated_request_info = {
        'id': req.id,
        'store_id': req.store_id,
        'product_id': req.product_id,
        'quantity': req.quantity,
        'requester_name': req.requester_name,
        'requester_contact': req.requester_contact,
        'status': req.status
    }

    return jsonify({'message': 'Request updated successfully', 'request': updated_request_info}), 200



    
###############################################################ROUTE FOR DELETING PRODUCTS(CLERK ONLY) ---------(WORKS)--------------#######################################################################
@app.route('/stores/<int:id>/product/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(id, product_id):
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

################################################ROUTES FOR DELETING REQUESTS(CLERK ONLY)---------(WORKS)--------------###################################################################################################
@app.route('/stores/<int:id>/request/<int:request_id>', methods=['DELETE'])
@jwt_required()
def delete_request(id, request_id):
    current_user = get_jwt_identity()
    
    if current_user['role'] == 'clerk':
        request = Request.query.filter_by(id=request_id, store_id=id).first()
        
        if request:
            db.session.delete(request)
            db.session.commit()
            return jsonify({'message': 'Request deleted successfully'}), 200
        else:
            return jsonify({'error': 'Request not found'}), 404
    else:
        return jsonify({"message": "Unauthorized"}), 401


############################################################################################################################################################################




if __name__ == '__main__':
    app.run(debug=True, port = 3000)
    
