"""
RentWheels — Vehicle Rental Web Application
Flask backend with DynamoDB + SNS integration
"""

import os
import uuid
import json
from datetime import datetime, date
from decimal import Decimal
from functools import wraps

import boto3
from botocore.exceptions import ClientError
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

# ──────────────────────────────────────────────
# Flask App Configuration
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'rentwheels-dev-secret-key-change-in-prod')

# ──────────────────────────────────────────────
# AWS Configuration
# Uses default credential chain:
#   - EC2 IAM Role (production)
#   - ~/.aws/credentials or env vars (development)
# ──────────────────────────────────────────────
AWS_REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-south-1')

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns_client = boto3.client('sns', region_name=AWS_REGION)

# Table references (populated after bootstrap)
users_table = None
vehicles_table = None
bookings_table = None
sns_topic_arn = None

# Default admin credentials (seeded on first run)
DEFAULT_ADMIN_USERNAME = 'admin'
DEFAULT_ADMIN_PASSWORD = 'admin123'
DEFAULT_ADMIN_EMAIL = 'admin@rentwheels.com'


# ──────────────────────────────────────────────
# AWS Resource Bootstrapping
# ──────────────────────────────────────────────
def wait_for_table_active(table_name):
    """Wait until a DynamoDB table is in ACTIVE status."""
    waiter = boto3.client('dynamodb', region_name=AWS_REGION).get_waiter('table_exists')
    waiter.wait(TableName=table_name, WaiterConfig={'Delay': 3, 'MaxAttempts': 20})


def create_table_if_not_exists(table_name, key_schema, attribute_definitions, gsi=None):
    """Create a DynamoDB table if it doesn't already exist."""
    try:
        table = dynamodb.Table(table_name)
        table.load()
        print(f"  [OK] Table '{table_name}' already exists.")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            raise

    print(f"  [..] Creating table '{table_name}'...")
    params = {
        'TableName': table_name,
        'KeySchema': key_schema,
        'AttributeDefinitions': attribute_definitions,
        'BillingMode': 'PAY_PER_REQUEST',
    }
    if gsi:
        params['GlobalSecondaryIndexes'] = gsi

    table = dynamodb.create_table(**params)
    wait_for_table_active(table_name)
    print(f"  [OK] Table '{table_name}' created successfully.")
    return table


def create_sns_topic():
    """Create or retrieve the SNS topic ARN."""
    global sns_topic_arn
    response = sns_client.create_topic(Name='VehicleBookingAlerts')
    sns_topic_arn = response['TopicArn']
    print(f"  [OK] SNS Topic ARN: {sns_topic_arn}")


def seed_admin_user():
    """Insert default admin account if it doesn't exist."""
    try:
        response = users_table.get_item(Key={'username': DEFAULT_ADMIN_USERNAME})
        if 'Item' in response:
            print(f"  [OK] Admin user '{DEFAULT_ADMIN_USERNAME}' already exists.")
            return
    except ClientError:
        pass

    users_table.put_item(Item={
        'username': DEFAULT_ADMIN_USERNAME,
        'password_hash': generate_password_hash(DEFAULT_ADMIN_PASSWORD),
        'role': 'admin',
        'email': DEFAULT_ADMIN_EMAIL,
        'full_name': 'System Admin',
        'created_at': datetime.utcnow().isoformat(),
    })
    print(f"  [OK] Admin user '{DEFAULT_ADMIN_USERNAME}' seeded (password: {DEFAULT_ADMIN_PASSWORD}).")


def bootstrap_aws():
    """Initialize all AWS resources on app startup."""
    global users_table, vehicles_table, bookings_table

    print("\n>> Bootstrapping AWS resources...\n")

    # --- Users table ---
    users_table = create_table_if_not_exists(
        table_name='Users',
        key_schema=[{'AttributeName': 'username', 'KeyType': 'HASH'}],
        attribute_definitions=[{'AttributeName': 'username', 'AttributeType': 'S'}],
    )

    # --- Vehicles table ---
    vehicles_table = create_table_if_not_exists(
        table_name='Vehicles',
        key_schema=[{'AttributeName': 'vehicle_id', 'KeyType': 'HASH'}],
        attribute_definitions=[{'AttributeName': 'vehicle_id', 'AttributeType': 'S'}],
    )

    # --- Bookings table (with GSI on username) ---
    bookings_table = create_table_if_not_exists(
        table_name='Bookings',
        key_schema=[{'AttributeName': 'booking_id', 'KeyType': 'HASH'}],
        attribute_definitions=[
            {'AttributeName': 'booking_id', 'AttributeType': 'S'},
            {'AttributeName': 'username', 'AttributeType': 'S'},
        ],
        gsi=[{
            'IndexName': 'username-index',
            'KeySchema': [{'AttributeName': 'username', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
    )

    # --- SNS Topic ---
    create_sns_topic()

    # --- Seed admin user ---
    seed_admin_user()

    print("\n>> AWS bootstrap complete.\n")


# ──────────────────────────────────────────────
# Auth Decorators
# ──────────────────────────────────────────────
def login_required(f):
    """Require authenticated session to access a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Require admin role to access a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated


# ──────────────────────────────────────────────
# Helper: convert Decimal to int/float for templates
# ──────────────────────────────────────────────
def decimal_to_num(obj):
    """Recursively convert Decimal values in a dict to int/float."""
    if isinstance(obj, list):
        return [decimal_to_num(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: decimal_to_num(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return int(obj) if obj == int(obj) else float(obj)
    return obj


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route('/')
def index():
    """Redirect root to login page."""
    if 'username' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))


# ─── LOGIN ────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('login'))

        try:
            response = users_table.get_item(Key={'username': username})
            user = response.get('Item')
        except ClientError:
            flash('Database error. Please try again.', 'error')
            return redirect(url_for('login'))

        if not user or not check_password_hash(user['password_hash'], password):
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

        # Set session
        session['username'] = user['username']
        session['role'] = user['role']
        session['full_name'] = user.get('full_name', username)

        flash(f'Welcome back, {session["full_name"]}!', 'success')

        if user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))

    return render_template('login.html')


# ─── REGISTER ─────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not all([full_name, email, username, password, confirm_password]):
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        # Check if username exists
        try:
            response = users_table.get_item(Key={'username': username})
            if 'Item' in response:
                flash('Username already taken. Choose another.', 'error')
                return redirect(url_for('register'))
        except ClientError:
            flash('Database error. Please try again.', 'error')
            return redirect(url_for('register'))

        # Create user (role defaults to 'user')
        users_table.put_item(Item={
            'username': username,
            'password_hash': generate_password_hash(password),
            'role': 'user',
            'email': email,
            'full_name': full_name,
            'created_at': datetime.utcnow().isoformat(),
        })

        flash('Account created successfully! Please sign in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ─── LOGOUT ───────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ─── ADMIN DASHBOARD ─────────────────────────
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        vehicle_type = request.form.get('vehicle_type', '').strip()
        category = request.form.get('category', '').strip()
        brand = request.form.get('brand', '').strip()
        model = request.form.get('model', '').strip()
        price_per_day = request.form.get('price_per_day', '0')
        image_url = request.form.get('image_url', '').strip()

        if not all([vehicle_type, category, brand, model, price_per_day]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('admin_dashboard'))

        # Validate category matches type
        valid_categories = {
            '2-Wheeler': ['Gear', 'Without Gear'],
            '4-Wheeler': ['Automatic', 'Manual', 'Semi-Automatic'],
        }
        if category not in valid_categories.get(vehicle_type, []):
            flash('Invalid category for the selected vehicle type.', 'error')
            return redirect(url_for('admin_dashboard'))

        vehicle_id = str(uuid.uuid4())
        vehicles_table.put_item(Item={
            'vehicle_id': vehicle_id,
            'vehicle_type': vehicle_type,
            'category': category,
            'brand': brand,
            'model': model,
            'price_per_day': Decimal(str(price_per_day)),
            'available': True,
            'image_url': image_url or '',
            'added_by': session['username'],
        })

        flash(f'{brand} {model} added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    # GET — fetch all vehicles
    try:
        response = vehicles_table.scan()
        vehicles = decimal_to_num(response.get('Items', []))
    except ClientError:
        vehicles = []
        flash('Failed to load vehicles.', 'error')

    return render_template('admin.html', vehicles=vehicles)


# ─── DELETE VEHICLE ───────────────────────────
@app.route('/admin/delete/<vehicle_id>')
@admin_required
def delete_vehicle(vehicle_id):
    try:
        vehicles_table.delete_item(Key={'vehicle_id': vehicle_id})
        flash('Vehicle deleted.', 'success')
    except ClientError:
        flash('Failed to delete vehicle.', 'error')
    return redirect(url_for('admin_dashboard'))


# ─── USER DASHBOARD ──────────────────────────
@app.route('/user')
@login_required
def user_dashboard():
    try:
        response = vehicles_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('available').eq(True)
        )
        vehicles = decimal_to_num(response.get('Items', []))
    except ClientError:
        vehicles = []
        flash('Failed to load vehicles.', 'error')

    return render_template('user.html', vehicles=vehicles)


# ─── PAYMENT ─────────────────────────────────
@app.route('/payment/<vehicle_id>', methods=['GET', 'POST'])
@login_required
def payment(vehicle_id):
    # Fetch vehicle
    try:
        response = vehicles_table.get_item(Key={'vehicle_id': vehicle_id})
        vehicle = response.get('Item')
        if not vehicle:
            flash('Vehicle not found.', 'error')
            return redirect(url_for('user_dashboard'))
        vehicle = decimal_to_num(vehicle)
    except ClientError:
        flash('Database error.', 'error')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        start_date = request.form.get('start_date', '')
        end_date = request.form.get('end_date', '')
        total_amount = request.form.get('total_amount', '0')

        if not start_date or not end_date:
            flash('Invalid dates.', 'error')
            return redirect(url_for('payment', vehicle_id=vehicle_id))

        # Create booking
        booking_id = str(uuid.uuid4())
        booking_item = {
            'booking_id': booking_id,
            'username': session['username'],
            'vehicle_id': vehicle_id,
            'start_date': start_date,
            'end_date': end_date,
            'total_amount': Decimal(str(total_amount)),
            'payment_status': 'completed',
            'booked_at': datetime.utcnow().isoformat(),
        }
        bookings_table.put_item(Item=booking_item)

        # Mark vehicle as unavailable
        vehicles_table.update_item(
            Key={'vehicle_id': vehicle_id},
            UpdateExpression='SET available = :val',
            ExpressionAttributeValues={':val': False},
        )

        # Publish SNS notification
        try:
            sns_message = {
                'booking_id': booking_id,
                'username': session['username'],
                'vehicle': f"{vehicle['brand']} {vehicle['model']}",
                'vehicle_type': vehicle['vehicle_type'],
                'dates': f"{start_date} to {end_date}",
                'amount': str(total_amount),
                'status': 'Payment Completed',
            }
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Subject='New Vehicle Booking - RentWheels',
                Message=json.dumps(sns_message, indent=2),
            )
            print(f"  [OK] SNS notification sent for booking {booking_id}")
        except ClientError as e:
            print(f"  [WARN] SNS publish failed: {e}")

        flash('Payment successful! Booking confirmed.', 'success')
        return redirect(url_for('ticket', booking_id=booking_id))

    # GET — Calculate total
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    num_days = 1
    total_amount = vehicle['price_per_day']

    if start_date and end_date:
        try:
            d1 = date.fromisoformat(start_date)
            d2 = date.fromisoformat(end_date)
            diff = (d2 - d1).days
            if diff > 0:
                num_days = diff
            total_amount = vehicle['price_per_day'] * num_days
        except ValueError:
            pass

    return render_template(
        'payment.html',
        vehicle=vehicle,
        start_date=start_date,
        end_date=end_date,
        num_days=num_days,
        total_amount=total_amount,
    )


# ─── TICKET ──────────────────────────────────
@app.route('/ticket/<booking_id>')
@login_required
def ticket(booking_id):
    try:
        response = bookings_table.get_item(Key={'booking_id': booking_id})
        booking = response.get('Item')
        if not booking:
            flash('Booking not found.', 'error')
            return redirect(url_for('user_dashboard'))
        booking = decimal_to_num(booking)
    except ClientError:
        flash('Database error.', 'error')
        return redirect(url_for('user_dashboard'))

    # Fetch vehicle details
    try:
        response = vehicles_table.get_item(Key={'vehicle_id': booking['vehicle_id']})
        vehicle = decimal_to_num(response.get('Item', {}))
    except ClientError:
        vehicle = {}

    return render_template('ticket.html', booking=booking, vehicle=vehicle)


# ──────────────────────────────────────────────
# App Entry Point
# ──────────────────────────────────────────────
if __name__ == '__main__':
    bootstrap_aws()
    app.run(host='0.0.0.0', port=5000, debug=True)
