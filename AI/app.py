from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from sqlalchemy import func
from collections import defaultdict
import os
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
import re

app = Flask(__name__)
app.config.from_object(Config)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://root:Sportgemeenschap1@localhost/sportconnect'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 280,
    'pool_timeout': 20,
    'pool_size': 30
}
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'  # Test key
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'  # Test key

db = SQLAlchemy(app)

# Association table for user preferences (interests)
user_preferences = db.Table('preference',
    db.Column('id', db.Integer, primary_key=True),
    db.Column('eventTypeID', db.Integer, db.ForeignKey('event_type.id')),
    db.Column('userID', db.Integer, db.ForeignKey('user.id'))
)

# Association table for event subscriptions
subscriptions = db.Table('subscription',
    db.Column('id', db.Integer, primary_key=True),
    db.Column('eventID', db.Integer, db.ForeignKey('event.id')),
    db.Column('userID', db.Integer, db.ForeignKey('user.id'))
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    birth_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    preferences = db.relationship('EventType', secondary='preference', backref='users')
    created_events = db.relationship('Event', backref='creator', lazy=True)
    subscribed_events = db.relationship('Event', secondary='subscription', backref='subscribed_users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_subscribed_to_event(self, event_id):
        return any(event.id == event_id for event in self.subscribed_events)

    def get_age(self):
        if self.birth_date:
            today = date.today()
            return today.year - self.birth_date.year - ((today.month, today.day) < (self.birth_date.month, self.birth_date.day))
        return None

class EventType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    icon = db.Column(db.String(255), nullable=False)  # URL or path to the icon
    subtypes = db.relationship('EventSubType', backref='event_type', lazy=True)

class EventSubType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    eventTypeID = db.Column(db.Integer, db.ForeignKey('event_type.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    events = db.relationship('Event', backref='subtype', lazy=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    eventSubTypeID = db.Column(db.Integer, db.ForeignKey('event_sub_type.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    availability = db.Column(db.String(20), nullable=False)  # Age category: '0-12', '13-17', '18-25', '26-40', '40+'
    address = db.Column(db.String(255), nullable=False)
    max_participants = db.Column(db.Integer, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def is_full(self):
        return len(self.subscribed_users) >= self.max_participants

    @staticmethod
    def get_age_categories():
        return ['13-17', '18-25', '26-40', '40+']

def calculate_age(birth_date):
    today = date.today()
    return today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

def is_age_appropriate(age_range, user_age):
    if not age_range or not user_age:
        return True
    
    age_parts = age_range.split('-')
    if len(age_parts) == 2:
        min_age = int(age_parts[0])
        max_age = int(age_parts[1]) if age_parts[1] != '+' else float('inf')
        return min_age <= user_age <= max_age
    elif age_parts[0].endswith('+'):
        min_age = int(age_parts[0].rstrip('+'))
        return user_age >= min_age
    return False

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one capital letter"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

# Authentication routes
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        selected_interests = request.form.getlist('interests')
        
        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'danger')
            return render_template('register.html', event_types=EventType.query.all())
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', event_types=EventType.query.all())
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html', event_types=EventType.query.all())
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html', event_types=EventType.query.all())
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)
        
        # Add selected interests
        for interest_id in selected_interests:
            event_type = EventType.query.get(interest_id)
            if event_type:
                new_user.preferences.append(event_type)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error during registration. Please try again.', 'danger')
            return render_template('register.html', event_types=EventType.query.all())
    
    return render_template('register.html', event_types=EventType.query.all())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/edit_interests', methods=['POST'])
def edit_interests():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    selected_interests = request.form.getlist('interests')
    
    # Clear existing preferences
    user.preferences.clear()
    
    # Add new preferences
    for interest_id in selected_interests:
        event_type = EventType.query.get(interest_id)
        if event_type:
            user.preferences.append(event_type)
    
    db.session.commit()
    flash('Your interests have been updated!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    event_types = EventType.query.all()
    now = datetime.now()
    
    return render_template('dashboard.html', user=user, event_types=event_types, now=now)

@app.route('/toggle_event_registration/<int:event_id>')
def toggle_event_registration(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    event = Event.query.get_or_404(event_id)
    
    # Check if user is interested in this event type
    if event.subtype.event_type not in user.preferences:
        flash('You can only subscribe to events that match your interests.', 'error')
        return redirect(url_for('index'))
    
    if user.is_subscribed_to_event(event_id):
        # Allow unsubscribe even if user is the creator
        user.subscribed_events.remove(event)
        flash('You have unsubscribed from this event.', 'info')
    else:
        if event.is_full():
            flash('Sorry, this event is already full.', 'error')
        else:
            # Check user's age against event age restrictions
            user_age = user.get_age()
            if user_age is not None:
                if not is_age_appropriate(event.availability, user_age):
                    flash('This event is not available for your age group.', 'error')
                    return redirect(request.referrer or url_for('dashboard'))
            
            user.subscribed_events.append(event)
            flash('You have subscribed to this event!', 'success')
    
    db.session.commit()
    return redirect(request.referrer or url_for('dashboard'))

# Event management routes
@app.route('/events')
def index():
    if 'user_id' not in session:
        return redirect(url_for('landing'))
    
    user = User.query.get(session['user_id'])
    # Get filter parameters
    event_type_id = request.args.get('event_type', type=int)
    age_category = request.args.get('age_category')
    date_filter = request.args.get('date_filter', 'all')
    created_by_me = request.args.get('created_by_me') == 'true'
    my_interests = request.args.get('my_interests') == 'true'
    
    # Base query for future events
    query = Event.query.filter(Event.date >= datetime.now())
    
    # Apply filters
    if event_type_id:
        query = query.join(EventSubType).join(EventType).filter(EventType.id == event_type_id)
    elif my_interests:
        # Filter by user's interests
        query = query.join(EventSubType).join(EventType).filter(EventType.id.in_([p.id for p in user.preferences]))
    
    if age_category:  # Filter by age category
        query = query.filter(Event.availability == age_category)
    
    if date_filter != 'all':
        now = datetime.now()
        if date_filter == 'today':
            query = query.filter(func.date(Event.date) == now.date())
        elif date_filter == 'week':
            # Get the start of the current week (Monday)
            week_start = now - timedelta(days=now.weekday())
            # Get the end of the current week (Sunday)
            week_end = week_start + timedelta(days=6, hours=23, minutes=59, seconds=59)
            query = query.filter(Event.date.between(week_start, week_end))
        elif date_filter == 'month':
            # Get the start of the current month
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            # Get the end of the current month
            if now.month == 12:
                next_month = now.replace(year=now.year + 1, month=1, day=1)
            else:
                next_month = now.replace(month=now.month + 1, day=1)
            month_end = next_month - timedelta(days=1, hours=23, minutes=59, seconds=59)
            query = query.filter(Event.date.between(month_start, month_end))
    
    if created_by_me:
        query = query.filter(Event.creator_id == session['user_id'])
    
    # Order events by date (closest first)
    query = query.order_by(Event.date.asc())
    
    # Get all events
    events = query.all()
    
    # If user is under 13, show no events
    if user and user.birth_date:
        user_age = calculate_age(user.birth_date)
        if user_age < 13:
            events = []
    
    return render_template('index.html', events=events, event_types=EventType.query.all(), age_categories=Event.get_age_categories(), user=user)

@app.route('/get_subtypes/<int:type_id>')
def get_subtypes(type_id):
    subtypes = EventSubType.query.filter_by(eventTypeID=type_id).all()
    return jsonify([{'id': s.id, 'name': s.name} for s in subtypes])

@app.route('/add_event', methods=['GET', 'POST'])
def add_event():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        event_subtype_id = request.form['event_subtype']
        date_str = request.form['date']
        
        # Validate that the event date is in the future
        event_date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
        if event_date <= datetime.now():
            flash('Event date must be in the future.', 'error')
            return redirect(url_for('add_event'))
            
        address = request.form['address']
        availability = request.form['availability']
        max_participants = int(request.form['max_participants'])

        new_event = Event(
            eventSubTypeID=event_subtype_id,
            date=event_date,
            address=address,
            availability=availability,
            max_participants=max_participants,
            creator_id=session['user_id']
        )

        try:
            db.session.add(new_event)
            # Auto-subscribe the creator to their event
            user = User.query.get(session['user_id'])
            user.subscribed_events.append(new_event)
            db.session.commit()
            flash('Event added successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding event. Please try again.', 'error')
            return redirect(url_for('add_event'))

    event_types = EventType.query.all()
    age_categories = Event.get_age_categories()
    now = datetime.now()
    return render_template('add_event.html', event_types=event_types, age_categories=age_categories, now=now)

@app.route('/edit_event/<int:id>', methods=['GET', 'POST'])
def edit_event(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    event = Event.query.get_or_404(id)
    
    # Check if the current user is the creator
    if event.creator_id != session['user_id']:
        flash('You do not have permission to edit this event.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        event.eventSubTypeID = request.form['event_subtype']
        event.date = datetime.strptime(request.form['date'], '%Y-%m-%dT%H:%M')
        event.address = request.form['address']
        event.availability = request.form['availability']
        event.max_participants = int(request.form['max_participants'])

        try:
            db.session.commit()
            flash('Event updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating event. Please try again.', 'error')
            return redirect(url_for('edit_event', id=id))

    event_types = EventType.query.all()
    age_categories = Event.get_age_categories()
    return render_template('edit_event.html', event=event, event_types=event_types, age_categories=age_categories)

@app.route('/delete_event/<int:id>')
def delete_event(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    event = Event.query.get_or_404(id)
    
    # Check if the current user is the creator
    if event.creator_id != session['user_id']:
        flash('You do not have permission to delete this event.', 'error')
        return redirect(url_for('index'))
    
    try:
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting event. Please try again.', 'error')
    
    return redirect(url_for('index'))

@app.route('/profile/update', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    action = request.form.get('action')
    
    if action == 'update_info':
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        birth_date = request.form.get('birth_date')
        
        if birth_date:
            try:
                user.birth_date = datetime.strptime(birth_date, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid birth date format.', 'error')
                return redirect(url_for('dashboard'))
        
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                flash('Username already taken.', 'error')
                return redirect(url_for('dashboard'))
            user.username = new_username
            session['username'] = new_username
        
        if new_email and new_email != user.email:
            if User.query.filter_by(email=new_email).first():
                flash('Email already registered.', 'error')
                return redirect(url_for('dashboard'))
            user.email = new_email
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
    
    elif action == 'update_password':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('dashboard'))
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('dashboard'))
        
        user.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully!', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/event/<int:id>')
def event_details(id):
    event = Event.query.get_or_404(id)
    return render_template('event_details.html', event=event)

def is_admin(user):
    return user.username == 'admin'  # Simple admin check - you can make this more sophisticated

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not is_admin(user):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all users and their preferences
    users = User.query.all()
    
    # Statistics for each age category
    age_stats = defaultdict(lambda: defaultdict(int))
    for user in users:
        if user.birth_date:
            age = calculate_age(user.birth_date)
            if age >= 13:  # Only count users 13 and older
                age_category = None
                if 13 <= age <= 17:
                    age_category = '13-17'
                elif 18 <= age <= 25:
                    age_category = '18-25'
                elif 26 <= age <= 40:
                    age_category = '26-40'
                elif age > 40:
                    age_category = '40+'
                
                if age_category:
                    for preference in user.preferences:
                        age_stats[age_category][preference.name] += 1
    
    # Convert to format suitable for Chart.js
    chart_data = {
        'labels': [event_type.name for event_type in EventType.query.all()],
        'datasets': []
    }
    
    colors = ['#FF6384', '#36A2EB', '#FFCE56', '#2E7D32']  # Changed 26-40 to dark green
    for i, (age_category, stats) in enumerate(age_stats.items()):
        values = [stats.get(event_type.name, 0) for event_type in EventType.query.all()]
        chart_data['datasets'].append({
            'label': age_category,
            'data': values,
            'backgroundColor': colors[i % len(colors)],
            'borderColor': colors[i % len(colors)],
            'borderWidth': 1
        })
    
    # Additional statistics
    total_users = len(users)
    users_with_birth_date = len([u for u in users if u.birth_date])
    total_events = Event.query.count()
    total_subscriptions = db.session.query(func.count(subscriptions.c.id)).scalar()
    
    # Event registration data per sport type
    sport_registration_data = defaultdict(int)
    for event in Event.query.all():
        sport_type = event.subtype.event_type.name
        sport_registration_data[sport_type] += 1
    
    # Convert sport registration data to format suitable for Chart.js
    sport_chart_data = {
        'labels': [event_type.name for event_type in EventType.query.all()],
        'datasets': [{
            'label': 'Number of Registered Events',
            'data': [sport_registration_data[event_type.name] for event_type in EventType.query.all()],
            'backgroundColor': '#4BC0C0',
            'borderColor': '#4BC0C0',
            'borderWidth': 1
        }]
    }
    
    # Event subscription data per sport type
    sport_subscription_data = defaultdict(int)
    for event in Event.query.all():
        sport_type = event.subtype.event_type.name
        sport_subscription_data[sport_type] += len(event.subscribed_users)
    
    # Convert sport subscription data to format suitable for Chart.js
    sport_chart_data = {
        'labels': [event_type.name for event_type in EventType.query.all()],
        'datasets': [{
            'label': 'Number of Subscribed Events',
            'data': [sport_subscription_data[event_type.name] for event_type in EventType.query.all()],
            'backgroundColor': '#4BC0C0',
            'borderColor': '#4BC0C0',
            'borderWidth': 2,
            'fill': False,
            'tension': 0.4
        }]
    }
    
    return render_template('admin.html', 
                         chart_data=chart_data,
                         sport_chart_data=sport_chart_data,
                         total_users=total_users,
                         users_with_birth_date=users_with_birth_date,
                         total_events=total_events,
                         total_subscriptions=total_subscriptions)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 