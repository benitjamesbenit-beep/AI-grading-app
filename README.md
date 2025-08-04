# AI-grading-appbash
Copy
Download
/project
│
├── .env                    # Environment variables (added)
├── app.py
├── models.py              # Added (separate model file)
├── requirements.txt
├── static/
│   └── styles.css
└── templates/
    ├── index.html
    ├── login.html
    ├── register.html
    └── admin.html
________________________________________
.env
ini
Copy
Download
SECRET_KEY=your_random_secret_key_here
STRIPE_SECRET_KEY=sk_test_your_stripe_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
DATABASE_URI=sqlite:///db.sqlite3
________________________________________
requirements.txt
plaintext
Copy
Download
Flask
Flask-SQLAlchemy
stripe
python-dotenv
werkzeug
models.py
python
Copy
Download
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Hashed password
    role = db.Column(db.String(20), default='free')
    subscription_plan = db.Column(db.String(20), default='free')
    feedback_history = db.Column(db.Text, default='[]')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
________________________________________
app.py
python
Copy
Download
import os
import uuid
import json
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from models import db, User
import stripe

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///db.sqlite3')
db.init_app(app)

# Stripe setup
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# Create tables
with app.app_context():
    db.create_all()

# Helper: Get current user
def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, role='free')
        user.set_password(password)  # Hash password
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    feedbacks = json.loads(user.feedback_history)
    return render_template('index.html', user=user, feedbacks=feedbacks)

@app.route('/api/grade', methods=['POST'])
def grade():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    feedbacks = json.loads(user.feedback_history)
    plan_limits = {'free': 3, 'basic': 50, 'pro': 200}
    if len(feedbacks) >= plan_limits.get(user.subscription_plan, 3):
        return jsonify({'error': 'Plan limit exceeded. Upgrade to analyze more.'}), 403

    data = request.get_json()
    submission_text = data.get('submission', '')
    feedback_text = generate_feedback(submission_text)  # AI logic placeholder

    feedbacks.append({
        'submission': submission_text,
        'feedback': feedback_text,
        'timestamp': str(uuid.uuid4())
    })
    user.feedback_history = json.dumps(feedbacks)
    db.session.commit()

    return jsonify({'feedback': feedback_text})

def generate_feedback(text):
    word_count = len(text.split())
    if word_count < 50:
        return "Your submission is too short. Aim for at least 50 words."
    elif "good" in text.lower():
        return "Excellent work! Your analysis is clear and detailed."
    else:
        return "Consider adding more examples or explanations."

# Stripe routes
@app.route('/subscribe/<plan>')
def subscribe(plan):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    session_url = create_stripe_session(user, plan)
    return redirect(session_url)

def create_stripe_session(user, plan):
    plan_prices = {'free': 0, 'basic': 500, 'pro': 1000}  # cents
    checkout_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'product_data': {'name': f'{plan.capitalize()} Plan'},
                'unit_amount': plan_prices[plan],
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('payment_success', _external=True) + f'?plan={plan}',
        cancel_url=url_for('dashboard', _external=True),
        metadata={'user_id': user.id, 'plan': plan}
    )
    return checkout_session.url

@app.route('/payment-success')
def payment_success():
    plan = request.args.get('plan')
    user = get_current_user()
    if user:
        user.subscription_plan = plan
        db.session.commit()
        flash(f'Upgraded to {plan} plan!', 'success')
    return redirect(url_for('dashboard'))

# Admin routes
@app.route('/admin')
def admin():
    user = get_current_user()
    if not user or user.role != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/make-admin/<int:user_id>')
def make_admin(user_id):
    admin_user = get_current_user()
    if not admin_user or admin_user.role != 'admin':
        flash('Permission denied.', 'danger')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    user.role = 'admin'
    db.session.commit()
    flash(f'{user.username} is now an admin.', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)
________________________________________
. templates/index.html (Updated JavaScript)
html
Copy
Download
Run
<!-- Add this to <head> for flash messages -->
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    <div class="flash-messages">
      {% for category, message in messages %}
        <div class="alert alert-{{ category }}">{{ message }}</div>
      {% endfor %}
    </div>
  {% endif %}
{% endwith %}

<!-- Updated JavaScript for error handling -->
<script>
  function analyze() {
    const text = document.getElementById('submission').value.trim();
    if (!text) {
      alert('Please enter text to analyze.');
      return;
    }
    fetch('/api/grade', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({submission: text})
    })
    .then(res => {
      if (!res.ok) throw res;
      return res.json();
    })
    .then(data => {
      document.getElementById('feedback').innerText = data.feedback;
      document.getElementById('feedback-section').style.display = 'block';
    })
    .catch(err => {
      err.json().then(e => alert(e.error || 'An error occurred.'));
    });
  }
</script>
. static/styles.css (Add Flash Messages)
css
Copy
Download
/* Add to styles.css */
.flash-messages {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 1000;
}
.alert {
  padding: 10px 20px;
  margin-bottom: 10px;
  border-radius: 5px;
}
.alert-success {
  background: #d4edda;
  color: #155724;
}
.alert-danger {
  background: #f8d7da;
  color: #721c24;
}

