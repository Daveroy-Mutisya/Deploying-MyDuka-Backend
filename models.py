from datetime import datetime
from enum import Enum
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates, relationship
import re

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(20), nullable=False)
    entries = db.Column(db.Integer, default=0, nullable=True)
    active = db.Column(db.Boolean, default=True)
      # Add this line

    def __init__(self, name, email, username, password, image, role):
        self.name = name
        self.email = email
        self.username = username
        self.password = password
        self.image = image
        self.role = role
        self.active = True

    @validates('email')
    def validate_email(self, key, email):
        assert '@' in email
        assert re.match(r"[^@]+@[^@]+\.[^@]+", email), "Invalid email format"
        return email
    
    @validates('password')
    def validate_password(self, key, password):
        assert len(password) > 8
        assert re.search(r"[A-Z]", password), "Password should contain at least one uppercase letter"
        assert re.search(r"[a-z]", password), "Password should contain at least one lowercase letter"
        assert re.search(r"[0-9]", password), "Password should contain at least one digit"
        assert re.search(r"[!@#$%^&*(),.?\":{}|<>]", password), "Password should contain at least one special character"
        return password

    def __repr__(self):
        return f"<User {self.id}, {self.username}, {self.role}, {self.email}, {self.password}>"

class Store(db.Model):
    __tablename__ = 'stores'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('stores', lazy=True))
    
    def __repr__(self):
        return f"Store(name='{self.name}')"
    
    def calculate_total_revenue(self):
        total_revenue = sum(product.calculate_revenue() for product in self.products)
        return total_revenue
    
    def calculate_total_profit(self):
        total_profit = sum(product.calculate_profit() for product in self.products)
        return total_profit

class Product(db.Model, SerializerMixin):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String, nullable=True)
    price = db.Column(db.Integer, nullable=True)
    condition = db.Column(db.String(100), nullable=True)
    stock_quantity = db.Column(db.Integer, nullable=True, default=0)
    spoil_quantity = db.Column(db.Integer, nullable=True, default=0)
    buying_price = db.Column(db.Integer, nullable=True)
    selling_price = db.Column(db.Integer, nullable=True)
    sales = db.Column(db.Integer, nullable=True)
    sales_date = db.Column(db.DateTime, nullable=True, default=datetime.utcnow) 
    store_id = db.Column(db.Integer, db.ForeignKey('stores.id'), nullable=False)
    store = db.relationship('Store', backref='products')

    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'image': self.image,
            'price': self.price,
            'condition': self.condition,
            'stock_quantity': self.stock_quantity,
            'spoilt_quantity': self.spoil_quantity,
            'buying_price': self.buying_price,
            'selling_price': self.selling_price,
            'sales': self.sales,
            'sales_date': self.sales_date,
            'store_id': self.store_id
           
        }

    def calculate_revenue(self):
        return self.selling_price * self.stock_quantity
    
    def calculate_profit(self):
        return (self.selling_price - self.buying_price) * self.stock_quantity

    def __repr__(self):
        return f"Product(name='{self.name}', store_id='{self.store_id}')"

class PaymentStatus(Enum):
    NOT_PAID = 'Not Paid'
    PAID = 'Paid'

class Payment(db.Model, SerializerMixin):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    store_id = db.Column(db.Integer, db.ForeignKey('stores.id'), nullable=False)
    store = db.relationship('Store', backref='payments')
    product_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.Enum(PaymentStatus), default=PaymentStatus.NOT_PAID, nullable=True)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    amount = db.Column(db.Integer)
    method = db.Column(db.String)
    due_date = db.Column(db.Date, nullable=True)

class Request(db.Model, SerializerMixin): 
    __tablename__ = 'requests'
    id = db.Column(db.Integer, primary_key=True)
    store_id = db.Column(db.Integer, db.ForeignKey('stores.id'), nullable=False)
    store = db.relationship('Store', backref='requests')
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    product = db.relationship('Product', backref='requests')
    quantity = db.Column(db.Integer, nullable=True)
    requester_name = db.Column(db.String(100), nullable=True)
    requester_contact = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(50), nullable=True, default='Pending')

    @validates('quantity')
    def validate_quantity(self, key, quantity):
        assert quantity > 0, "Quantity must be a positive integer"
        return quantity
