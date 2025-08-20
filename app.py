from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv
import csv
from io import StringIO
from flask import make_response

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key')  # Load SECRET_KEY from .env
ADMIN_KEY = os.environ.get('ADMIN_KEY', 'fallback-admin-key')  # Load ADMIN_KEY from .env

if os.environ.get('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = False  # ADD ONLY THIS LINE

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def get_user_context():
    """Get common user context for templates"""
    context = {}
    if current_user.is_authenticated:
        initial = QuizAttempt.query.filter_by(
            user_id=current_user.id, 
            quiz_type='initial'
        ).first()
        final = QuizAttempt.query.filter_by(
            user_id=current_user.id, 
            quiz_type='final'
        ).first()
        
        progress = UserProgress.query.filter_by(user_id=current_user.id).first()
        completed_tasks = progress.completed_tasks.split(',') if progress and progress.completed_tasks else []
        
        badges = {
            'bronze': len([t for t in completed_tasks if t]) >= 3,
            'silver': len([t for t in completed_tasks if t]) >= 6,
            'gold': len([t for t in completed_tasks if t]) >= 10,
            'diamond': False
        }
        
        if initial and final:
            improvement = final.score - initial.score
            improvement_percent = (improvement / initial.score * 100) if initial.score > 0 else 0
            if improvement_percent >= 30:
                badges['diamond'] = True
            context['initial_score'] = initial.score
            context['final_score'] = final.score
        
        context['badges'] = badges
    
    return context

@app.context_processor
def inject_user_data():
    """Make user data available to all templates"""
    if current_user.is_authenticated:
        return get_user_context()
    return {}

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    quiz_attempts = db.relationship('QuizAttempt', backref='user', lazy=True)
    progress = db.relationship('UserProgress', backref='user', uselist=False)
    feedback = db.relationship('Feedback', backref='user', uselist=False)

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_type = db.Column(db.String(20), nullable=False)  # 'initial' or 'final'
    score = db.Column(db.Integer, nullable=False)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    current_task = db.Column(db.Integer, default=0)
    completed_tasks = db.Column(db.String(200), default='')  # Store as comma-separated values
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ease_of_use = db.Column(db.String(20), nullable=False)  # 'yes', 'neutral', 'no'
    confidence_level = db.Column(db.String(20), nullable=False)  # 'yes', 'neutral', 'no'
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

# Login manager loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes 
@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another one.', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        # Create user progress entry
        progress = UserProgress(user_id=user.id)
        db.session.add(progress)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Check if user has taken initial quiz
    initial_quiz = QuizAttempt.query.filter_by(
        user_id=current_user.id, 
        quiz_type='initial'
    ).first()
    
    # Check if user has taken final quiz
    final_quiz = QuizAttempt.query.filter_by(
        user_id=current_user.id, 
        quiz_type='final'
    ).first()
    
    # Get user progress
    progress = UserProgress.query.filter_by(user_id=current_user.id).first()
    
    # Calculate completion percentage
    completed_tasks = progress.completed_tasks.split(',') if progress.completed_tasks else []
    completion_percentage = len([t for t in completed_tasks if t]) * 10  # 10% per task
    
    # Check for earned badges
    badges = {
        'bronze': len([t for t in completed_tasks if t]) >= 3,
        'silver': len([t for t in completed_tasks if t]) >= 6,
        'gold': len([t for t in completed_tasks if t]) >= 10,
        'diamond': False  # Will be set after final quiz
    }
    
    # Award diamond badge if improvement > 30%
    if initial_quiz and final_quiz:
        improvement = final_quiz.score - initial_quiz.score
        improvement_percent = (improvement / initial_quiz.score * 100) if initial_quiz.score > 0 else 0
        if improvement_percent >= 30:
            badges['diamond'] = True
    
    return render_template('dashboard.html', 
                         initial_quiz=initial_quiz,
                         final_quiz=final_quiz,
                         has_taken_final=final_quiz is not None,
                         progress=progress,
                         completion_percentage=completion_percentage,
                         badges=badges)

# Quiz questions
QUIZ_QUESTIONS = [
    {
        'id': 1,
        'question': "You receive an email saying you've won a prize, but you don't remember entering any contest. It asks you to click a link. What should you do?",
        'options': {
            'A': 'Click the link to see what you won',
            'B': 'Forward it to your friends',
            'C': 'Delete the email or mark it as spam',
            'D': 'Reply and ask for more information'
        },
        'correct': 'C'
    },
    {
        'id': 2,
        'question': "Which of the following is the best practice for creating a secure password?",
        'options': {
            'A': 'johnsmith2024',
            'B': 'JOHNSMITH',
            'C': '8274928471',
            'D': '@J0hn$2024#'
        },
        'correct': 'D'
    },
    {
        'id': 3,
        'question': "Which of these is the most likely scam website?",
        'options': {
            'A': 'amazon.co.uk',
            'B': 'paypal.com',
            'C': 'amaz0n-offer-prize.xyz',
            'D': 'google.com'
        },
        'correct': 'C'
    },
    {
        'id': 4,
        'question': "You get a message on WhatsApp asking for money urgently from a friend. What should you do first?",
        'options': {
            'A': 'Send the money immediately',
            'B': 'Call your friend to confirm',
            'C': 'Block your friend',
            'D': 'Forward the message to others'
        },
        'correct': 'B'
    },
    {
        'id': 5,
        'question': "Out of the following password types, which one is the weakest?",
        'options': {
            'A': 'MyPass123!',
            'B': 'abcdefgh',
            'C': '72638829',
            'D': 'S@feLife2024'
        },
        'correct': 'B'
    },
    {
        'id': 6,
        'question': "You are using a public computer in a cafe. What is the most secure action?",
        'options': {
            'A': 'Log into your bank account and save the password',
            'B': 'Use incognito mode and log out after use',
            'C': 'Leave email open after checking',
            'D': 'Allow browser to remember your login'
        },
        'correct': 'B'
    },
    {
        'id': 7,
        'question': "What is the main reason not to reuse the same password on multiple websites?",
        'options': {
            'A': "It's hard to remember different ones",
            'B': 'One hacked account can expose others',
            'C': 'It takes longer to log in',
            'D': 'You might get locked out'
        },
        'correct': 'B'
    },
    {
        'id': 8,
        'question': "An app requests permission to access your microphone, contacts, and location — but it's just a calculator app. What should you do?",
        'options': {
            'A': 'Grant all permissions so it works properly',
            'B': 'Check permissions and deny unnecessary ones',
            'C': 'Turn off your phone',
            'D': "Accept them; it's just a calculator"
        },
        'correct': 'B'
    },
    {
        'id': 9,
        'question': "You get an unexpected email with an attachment titled 'Invoice.pdf' from someone you don't know. What should you do?",
        'options': {
            'A': 'Open it and check',
            'B': 'Reply to ask for details',
            'C': 'Delete it or scan with antivirus',
            'D': 'Forward it to a colleague'
        },
        'correct': 'C'
    },
    {
        'id': 10,
        'question': "You're shopping online and reach a payment page. Which of these is a sign of a secure website?",
        'options': {
            'A': 'The site looks colorful',
            'B': 'The price is extremely low',
            'C': "The URL starts with 'https://'",
            'D': "There's a lot of text on the homepage"
        },
        'correct': 'C'
    }
]

@app.route('/quiz/initial')
@login_required
def take_initial_quiz():
    print("Quiz route hit!") 
    print(f"Questions: {len(QUIZ_QUESTIONS)}")

    # Check if already taken
    existing_quiz = QuizAttempt.query.filter_by(
        user_id=current_user.id,
        quiz_type='initial'
    ).first()
    
    if existing_quiz:
        flash('You have already taken the initial quiz.', 'info')
        return redirect(url_for('dashboard'))
    
    return render_template('quiz.html', 
                         questions=QUIZ_QUESTIONS,
                         quiz_type='initial',
                         title='Initial Assessment Quiz')



@app.route('/quiz/submit', methods=['POST'])
@login_required
def submit_quiz():
    quiz_type = request.form.get('quiz_type')
    score = 0
    
    # Calculate score
    for question in QUIZ_QUESTIONS:
        answer = request.form.get(f'question_{question["id"]}')
        if answer == question['correct']:
            score += 1
    
    # Save quiz attempt
    quiz_attempt = QuizAttempt(
        user_id=current_user.id,
        quiz_type=quiz_type,
        score=score
    )
    db.session.add(quiz_attempt)
    db.session.commit()
    
    if quiz_type == 'initial':
     progress = UserProgress.query.filter_by(user_id=current_user.id).first()
     if progress and progress.current_task == 0:
        progress.current_task = 1
        db.session.commit()
    else:
     flash(f'Final quiz completed! Your score: {score}/10', 'success')
    return redirect(url_for('results'))

# Learning Tasks Data
TASKS = {
    1: {
        'title': 'Spotting Phishing Emails',
        'content': '''Phishing emails pretend to be from someone you trust to trick you into clicking malicious links. 
        They often promise prizes, use urgent language, or come from odd-looking addresses.
        
        Tips: Hover over links to see real URLs, watch for spelling mistakes, go directly to official websites.''',
        'questions': [
            {
                'q': 'You get an email from "support@yourbank-security.com" asking to reset your password. What do you do?',
                'options': {
                    'A': 'Click the link',
                    'B': 'Log into bank site separately',
                    'C': 'Reply asking if real',
                    'D': 'Ignore it'
                },
                'correct': 'B',
                'feedback': {
                    'correct': 'Correct! Always log in directly instead of trusting email links.',
                    'wrong': 'No - Option B is correct. Never trust unexpected email links.'
                }
            },
            {
                'q': 'An email says "Your account will close in 24h!" with typos. What\'s the red flag?',
                'options': {
                    'A': 'The deadline',
                    'B': 'Spelling/grammar errors',
                    'C': 'It has a link',
                    'D': 'It\'s marked important'
                },
                'correct': 'B',
                'feedback': {
                    'correct': 'Correct! Spelling mistakes often signal scams.',
                    'wrong': 'No - Option B is correct. Legitimate organizations proofread carefully.'
                }
            }
        ]
    },

    2: {
        'title': 'Creating Strong Passwords',
        'content': '''A strong password is like a sturdy lock on your account—it's long, unique, and hard to guess. Mixing different character types makes it tougher for hackers to break in. Think of it as a custom combination no one else knows. Regularly updating and avoiding reuse makes sure your "lock" stays strong over time.
        
        Tips:
        • Use at least 12 characters
        • Mix uppercase, lowercase, numbers, and symbols
        • Avoid personal info (names, birthdays) or common words
        
        Why It Matters:
        Stronger passwords slow down or stop hackers' automated tools, keeping your personal data secure.''',
        'questions': [
            {
                'q': 'Which of the following is the strongest password?',
                'options': {
                    'A': '123456789',
                    'B': 'Password123',
                    'C': 'Myp@ssw0rd!',
                    'D': 'Qwerty123'
                },
                'correct': 'C',
                'feedback': {
                    'correct': 'Correct! This uses a mix of characters and symbols.',
                    'wrong': 'No - Option C is correct. It combines letters, numbers, and symbols.'
                }
            },
            {
                'q': 'What makes a password weak?',
                'options': {
                    'A': 'It’s short and uses common words',
                    'B': 'It contains symbols',
                    'C': 'It’s long and unique',
                    'D': 'It has uppercase letters'
                },
                'correct': 'A',
                'feedback': {
                    'correct': 'Correct! Short, predictable passwords are easily guessed.',
                    'wrong': 'No - Option A is correct; common and short passwords are not secure.'
                }
            }
        ]
    },

    3: {
        'title': 'Recognizing Scam Websites',
        'content': '''Scammers create fake websites that look like the real thing by changing a letter or domain ending (e.g., "amaz0n.xyz"). If you enter your info there, it goes straight to criminals. Fake sites might also copy the exact design or colors of the real site to seem authentic. Learning to examine URLs closely can save you from identity theft and financial loss.
        
        Tips:
        • Always look for "https://" and the lock icon
        • Double-check the exact spelling of the domain
        • Type the URL yourself or use a saved bookmark
        
        Why It Matters:
        Using a wrong site hands your login or payment details directly to scammers.''',
        'questions': [
            {
                'q': 'Which of these is most likely a fake website?',
                'options': {
                    'A': 'www.amazon.com',
                    'B': 'www.amaz0n-offers.xyz',
                    'C': 'https://www.bank.com',
                    'D': 'www.google.com'
                },
                'correct': 'B',
                'feedback': {
                    'correct': 'Correct! Misspelled or odd domains often indicate scams.',
                    'wrong': 'No - Option B is correct; scammers mimic real names with slight changes.'
                }
            },
            {
                'q': 'What is a good way to check if a site is safe?',
                'options': {
                    'A': 'Click any link you get via email',
                    'B': 'Search it on social media',
                    'C': 'Look for "https://" and the lock icon',
                    'D': 'Check how flashy it looks'
                },
                'correct': 'C',
                'feedback': {
                    'correct': 'Correct! Secure sites start with https:// and show a lock.',
                    'wrong': 'No - Option C is correct. The lock and https:// show encryption.'
                }
            }
        ]
    },

    4: {
        'title': 'Verifying Strange Payment Requests',
        'content': '''Scammers sometimes hijack friends' messaging accounts to ask for money. Always double-check by calling or video-chatting before sending anything. Impersonators often use urgent or emotional stories to rush you. Trust your instincts—if something feels off, take extra steps to confirm.
        
        Tips:
        • Use a second channel (phone/video) to confirm
        • Notice changes in tone or wording
        • If you’re unsure, don’t send money
        
        Why It Matters:
        Verifying requests prevents you from sending money to criminals posing as people you trust.''',
        'questions': [
            {
                'q': 'Your friend messages urgently asking for money—what should you do?',
                'options': {
                    'A': 'Send the money quickly',
                    'B': 'Ask them to call or video chat to confirm',
                    'C': 'Ignore it',
                    'D': 'Tell others to send money too'
                },
                'correct': 'B',
                'feedback': {
                    'correct': 'Correct! Always verify using another method.',
                    'wrong': 'No - Option B is correct; confirming avoids scams.'
                }
            },
            {
                'q': 'What’s a sign the message might be fake?',
                'options': {
                    'A': 'Your friend uses their usual tone',
                    'B': 'They offer to pay back tomorrow',
                    'C': 'The message feels urgent or emotional',
                    'D': 'It comes from their usual number'
                },
                'correct': 'C',
                'feedback': {
                    'correct': 'Correct! Scammers often use urgency to pressure victims.',
                    'wrong': 'No - Option C is correct; urgency is a red flag.'
                }
            }
        ]
    },

    5: {
        'title': 'Safe Use of Public Computers',
        'content': '''Public computers (in cafés, libraries) can save your data or have hidden malware. Using privacy modes and logging out keeps your info private. Anyone using the same machine can see your browsing history or saved passwords. Always clear your session so no traces remain behind.
        
        Tips:
        • Open an incognito/private browser window
        • Decline any "save password" prompts
        • Manually log out and close the browser when done
        
        Why It Matters:
        Leaving behind saved credentials or history lets others access your accounts.''',
        'questions': [
            {
                'q': 'What should you always do on a public computer?',
                'options': {
                    'A': 'Save your password to remember it',
                    'B': 'Use private mode and log out after',
                    'C': 'Leave tabs open for the next user',
                    'D': 'Print your password for safety'
                },
                'correct': 'B',
                'feedback': {
                    'correct': 'Correct! Private mode and logging out protect your info.',
                    'wrong': 'No - Option B is correct; it prevents others from seeing your data.'
                }
            },
            {
                'q': 'Why is using incognito mode helpful on public computers?',
                'options': {
                    'A': 'It makes your screen brighter',
                    'B': 'It blocks viruses',
                    'C': 'It stops saving history and passwords',
                    'D': 'It lets you access hidden sites'
                },
                'correct': 'C',
                'feedback': {
                    'correct': 'Correct! Incognito doesn’t store history or credentials.',
                    'wrong': 'No - Option C is correct; it helps prevent data leakage.'
                }
            }
        ]
    },

    6: {
        'title': 'Avoiding Password Reuse',
        'content': '''Using the same password on multiple sites lets hackers use one stolen password to break into all your accounts ("credential stuffing"). Creating unique passwords prevents this domino effect. Many breaches go unreported for months—if you reuse a password, you may not know your other accounts are at risk. Unique credentials are your best defense.
        
        Tips:
        • Use a password manager to create/store unique passwords
        • If needed, use a formula (e.g., MyBase! + site name)
        • Update passwords immediately if a breach is reported
        
        Why It Matters:
        Unique passwords ensure that one breach doesn't expose all your accounts.''',
        'questions': [
            {
                'q': 'Why should you avoid reusing passwords?',
                'options': {'A': 'It\'s hard to remember', 'B': 'One breach can expose others', 'C': 'It takes longer to type'},
                'correct': 'B',
                'feedback': {'correct': 'Correct! A single hack can cascade across your accounts.',
                           'wrong': 'No - Option B is correct; unique passwords isolate risks.'}
            },
            {
                'q': 'You hear Site X was breached—what\'s your first step?',
                'options': {'A': 'Change that site\'s password only', 'B': 'Change the reused password on all sites'},
                'correct': 'B',
                'feedback': {'correct': 'Correct! Every account sharing that password is at risk.',
                           'wrong': 'No - Option B is correct; updating only one leaves others vulnerable.'}
            }
        ]
    },
    7: {
        'title': 'Managing App Permissions',
        'content': '''Apps often request more access than they need. Granting unnecessary permissions (like mic or contacts) lets apps collect data you may not want to share. Some apps even run in the background and track your location or listen to conversations. Reviewing permissions keeps you in control of your personal information.
        
        Tips:
        • Before installing, review requested permissions
        • Deny any that aren\'t needed for basic app function
        • Later, go to your phone\'s settings to revoke permissions
        
        Why It Matters:
        Limiting permissions protects your privacy and prevents unwanted data collection.''',
        'questions': [
            {
                'q': 'A flashlight app asks for access to your contacts—what do you do?',
                'options': {'A': 'Deny contacts, allow flashlight', 'B': 'Grant all permissions'},
                'correct': 'A',
                'feedback': {'correct': 'Correct! Only grant what\'s essential.',
                           'wrong': 'No - Option A is correct; extra permissions pose privacy risks.'}
            },
            {
                'q': 'You want to revoke an app\'s permission later—how?',
                'options': {'A': 'Reinstall the app', 'B': 'Go to phone Settings → Permissions'},
                'correct': 'B',
                'feedback': {'correct': 'Correct! You can toggle permissions in settings anytime.',
                           'wrong': 'No - Option B is correct; reinstalling isn\'t needed when settings handle it.'}
            }
        ]
    },
    8: {
        'title': 'Handling Unknown Email Attachments',
        'content': '''Email attachments from unknown senders can hide malware. Opening or enabling them can infect your device or steal files. Some attachments even hide harmful scripts that run once you enable editing. Staying cautious about any unexpected file keeps your system and data safe.
        
        Tips:
        • If the sender is unfamiliar, delete the email
        • If you think it might be genuine, scan the attachment with antivirus first
        • Never enable macros or editing in unexpected documents
        
        Why It Matters:
        Stopping malware at the email stage prevents data loss, ransomware, or hacking.''',
        'questions': [
            {
                'q': 'You get "Invoice.pdf" from a stranger—what do you do?',
                'options': {'A': 'Scan with antivirus or delete', 'B': 'Open to see what it is'},
                'correct': 'A',
                'feedback': {'correct': 'Correct! Scanning or deleting avoids hidden threats.',
                           'wrong': 'No - Option A is correct; opening suspicious files risks infection.'}
            },
            {
                'q': 'The file asks you to "Enable editing"—should you?',
                'options': {'A': 'Yes', 'B': 'No'},
                'correct': 'B',
                'feedback': {'correct': 'Correct! Enabling editing can activate dangerous macros.',
                           'wrong': 'No - Option B is correct; safe files don\'t need you to enable macros.'}
            }
        ]
    },
    9: {
        'title': 'Verifying Secure Websites',
        'content': '''Secure websites use HTTPS (the "s" stands for secure) to encrypt data between you and the site. A padlock icon in your browser\'s address bar indicates this protection. Without encryption, anyone on the same network can sniff your passwords or payment details. Always look for these signs before sharing personal info.
        
        Tips:
        • Always look for "https://" before entering any sensitive info
        • Click the lock icon to view certificate details
        • Avoid sites showing "Not secure" warnings
        
        Why It Matters:
        Encryption stops eavesdroppers from intercepting passwords, credit-card numbers, and personal data.''',
        'questions': [
            {
                'q': 'You\'re shopping and see "http://" (no "s")—what do you do?',
                'options': {'A': 'Proceed anyway', 'B': 'Leave and find "https://"'},
                'correct': 'B',
                'feedback': {'correct': 'Correct! Only HTTPS guarantees encrypted connections.',
                           'wrong': 'No - Option B is correct; HTTP is unprotected.'}
            },
            {
                'q': 'You notice a broken lock icon—should you enter your card details?',
                'options': {'A': 'Yes', 'B': 'No'},
                'correct': 'B',
                'feedback': {'correct': 'Correct! A broken lock means data isn\'t secure.',
                           'wrong': 'No - Option B is correct; never share sensitive info on an insecure page.'}
            }
        ]
    },
    10: {
        'title': 'Two-Factor Authentication (2FA)',
        'content': '''Two-Factor Authentication adds a second step (like a text code or app prompt) after your password. Even if someone guesses your password, they still can\'t access your account without that second factor. You might get this via SMS, email, or an authenticator app. Enabling 2FA turns your account into a two-lock system—much harder for attackers to breach.
        
        Tips:
        • Enable 2FA wherever available (banks, email, social media)
        • Use an authenticator app for stronger security than SMS codes
        • Keep backup codes in a safe place
        
        Why It Matters:
        2FA blocks attackers who have your password, greatly reducing the risk of account takeovers.''',
        'questions': [
            {
                'q': 'What is Two-Factor Authentication?',
                'options': {'A': 'A way to use two devices at once', 'B': 'A security step after your password', 'C': 'A browser extension', 'D': 'Saving two passwords'},
                'correct': 'B',
                'feedback': {'correct': 'Correct! 2FA adds an extra verification step.',
                           'wrong': 'No - Option B is correct; 2FA is a second security check.'}
            },
            {
                'q': 'Which 2FA method is stronger?',
                'options': {'A': 'SMS code', 'B': 'Authenticator app (e.g., Google Authenticator)'},
                'correct': 'B',
                'feedback': {'correct': 'Correct! Authenticator apps are harder to intercept than SMS.',
                           'wrong': 'No - Option B is correct; SMS can be intercepted or SIM-swapped.'}
            }
        ]
    }
    # Add tasks 2-10 here following same structure
}

@app.route('/task/<int:task_id>')
@login_required
def task(task_id):
    progress = UserProgress.query.filter_by(user_id=current_user.id).first()
    
    completed_tasks = progress.completed_tasks.split(',') if progress.completed_tasks else []
    if task_id > progress.current_task + 1 and str(task_id) not in completed_tasks:
        flash('Complete previous tasks first!', 'error')
        return redirect(url_for('dashboard'))
    
    task_data = TASKS.get(task_id, None)
    if not task_data:
        flash('Task not found!', 'error')
        return redirect(url_for('dashboard'))
    
    is_completed = str(task_id) in completed_tasks
    
    # Create enumerated questions for template
    enumerated_questions = []
    if 'questions' in task_data:
        for idx, question in enumerate(task_data['questions']):
            enumerated_questions.append({'index': idx, 'question': question})
    
    return render_template('task.html', 
                         task_id=task_id,
                         task=task_data,
                         enumerated_questions=enumerated_questions,
                         show_content=True,
                         is_completed=is_completed)

@app.route('/task/<int:task_id>/exercise')
@login_required
def task_exercise(task_id):
    progress = UserProgress.query.filter_by(user_id=current_user.id).first()
    completed_tasks = progress.completed_tasks.split(',') if progress.completed_tasks else []
    
    # Check if task is already completed
    if str(task_id) in completed_tasks:
        flash('You have already completed this task. You can review the content.', 'info')
        return redirect(url_for('task', task_id=task_id))
        #j
    task_data = TASKS.get(task_id, None)
    if not task_data:
        return redirect(url_for('dashboard'))
    
    # Create enumerated questions for template
    enumerated_questions = []
    if 'questions' in task_data:
        for idx, question in enumerate(task_data['questions']):
            enumerated_questions.append({'index': idx, 'question': question})
    
    return render_template('task.html',
                         task_id=task_id,
                         task=task_data,
                         enumerated_questions=enumerated_questions,
                         show_content=False,
                         is_completed=False)

@app.route('/task/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    progress = UserProgress.query.filter_by(user_id=current_user.id).first()
    
    # Mark task as completed
    completed = progress.completed_tasks.split(',') if progress.completed_tasks else []
    if str(task_id) not in completed:
        completed.append(str(task_id))
        progress.completed_tasks = ','.join(completed)
        
        # Update current_task to next task
        if task_id >= progress.current_task:
            progress.current_task = task_id + 1  # Move to next task
        
        db.session.commit()
    
    flash(f'Task {task_id} completed! Task {task_id + 1} is now unlocked.', 'success')
    return redirect(url_for('dashboard'))

# Add these routes after your task routes

@app.route('/quiz/final')
@login_required
def final_quiz():
    progress = UserProgress.query.filter_by(user_id=current_user.id).first()
    
    # Check if all tasks are completed
    completed = progress.completed_tasks.split(',') if progress.completed_tasks else []
    if len([t for t in completed if t]) < 10:
        flash('Complete all 10 tasks before taking the final quiz!', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if already taken
    final_attempt = QuizAttempt.query.filter_by(
        user_id=current_user.id,
        quiz_type='final'
    ).first()
    
    if final_attempt:
        return redirect(url_for('results'))
    
    return render_template('quiz.html', 
                         questions=QUIZ_QUESTIONS,
                         quiz_type='final',
                         title='Final Assessment Quiz')

@app.route('/results')
@login_required
def results():
    # Get both quiz attempts
    initial = QuizAttempt.query.filter_by(
        user_id=current_user.id,
        quiz_type='initial'
    ).first()
    
    final = QuizAttempt.query.filter_by(
        user_id=current_user.id,
        quiz_type='final'
    ).first()
    
    if not initial or not final:
        flash('Complete both quizzes to see results!', 'error')
        return redirect(url_for('dashboard'))
    
    # Calculate improvement
    improvement = final.score - initial.score
    improvement_percent = (improvement / initial.score * 100) if initial.score > 0 else 0

    return render_template('final.html',
                        initial_score=initial.score,
                        final_score=final.score,
                        improvement=improvement,
                        improvement_percent=improvement_percent)
    
@app.route('/submit_feedback', methods=['POST'])
@login_required
def submit_feedback():
    ease_of_use = request.form.get('ease_of_use')
    confidence_level = request.form.get('confidence_level')
    
    # Check if feedback already exists
    existing_feedback = Feedback.query.filter_by(user_id=current_user.id).first()
    
    if existing_feedback:
        flash('You have already submitted feedback!', 'info')
    else:
        feedback = Feedback(
            user_id=current_user.id,
            ease_of_use=ease_of_use,
            confidence_level=confidence_level
        )
        db.session.add(feedback)
        db.session.commit()
    
    return redirect(url_for('completion'))

@app.route('/completion')
@login_required
def completion():
    return render_template('completion.html')

import csv
from io import StringIO
from flask import make_response

@app.route('/admin/export-data')
@login_required
def export_data():
    # Simple admin check - you can enhance this
    if current_user.username not in ['admin', 'researcher']:  # Add your admin usernames
        flash('Access denied. Admin only.', 'error')
        return redirect(url_for('dashboard'))
    
    # Create CSV in memory
    si = StringIO()
    writer = csv.writer(si)
    
    # Write headers
    writer.writerow([
        'User ID', 'Username', 'Registration Date',
        'Initial Quiz Score', 'Initial Quiz Date',
        'Final Quiz Score', 'Final Quiz Date',
        'Score Improvement', 'Improvement Percentage',
        'Tasks Completed', 'Completion Percentage',
        'Ease of Use', 'Confidence Level',
        'Bronze Badge', 'Silver Badge', 'Gold Badge', 'Diamond Badge'
    ])
    
    # Get all users
    users = User.query.all()
    
    for user in users:
        # Get quiz attempts
        initial_quiz = QuizAttempt.query.filter_by(user_id=user.id, quiz_type='initial').first()
        final_quiz = QuizAttempt.query.filter_by(user_id=user.id, quiz_type='final').first()
        
        # Get progress
        progress = UserProgress.query.filter_by(user_id=user.id).first()
        completed_tasks = progress.completed_tasks.split(',') if progress and progress.completed_tasks else []
        tasks_completed = len([t for t in completed_tasks if t])
        completion_percentage = tasks_completed * 10
        
        # Get feedback
        feedback = Feedback.query.filter_by(user_id=user.id).first()
        
        # Calculate improvement
        improvement = 0
        improvement_percent = 0
        if initial_quiz and final_quiz:
            improvement = final_quiz.score - initial_quiz.score
            improvement_percent = (improvement / initial_quiz.score * 100) if initial_quiz.score > 0 else 0
        
        # Check badges
        bronze = tasks_completed >= 3
        silver = tasks_completed >= 6
        gold = tasks_completed >= 10
        diamond = improvement_percent >= 30
        
        # Write row
        writer.writerow([
            user.id,
            user.username,
            user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else '',
            initial_quiz.score if initial_quiz else '',
            initial_quiz.attempted_at.strftime('%Y-%m-%d %H:%M:%S') if initial_quiz else '',
            final_quiz.score if final_quiz else '',
            final_quiz.attempted_at.strftime('%Y-%m-%d %H:%M:%S') if final_quiz else '',
            improvement if initial_quiz and final_quiz else '',
            f"{improvement_percent:.1f}" if initial_quiz and final_quiz else '',
            tasks_completed,
            completion_percentage,
            feedback.ease_of_use if feedback else '',
            feedback.confidence_level if feedback else '',
            'Yes' if bronze else 'No',
            'Yes' if silver else 'No',
            'Yes' if gold else 'No',
            'Yes' if diamond else 'No'
        ])
    
    # Create response
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=cybersafe_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    output.headers["Content-type"] = "text/csv"
    
    return output

# Add admin dashboard route
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_key = request.form.get('admin_key')
        if admin_key == ADMIN_KEY:
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin key', 'error')
    return render_template('admin_login.html')

@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    # Admin dashboard logic
    return render_template('admin.html')

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        print("Database initialized!")

# Create tables on first run
with app.app_context():
    db.create_all()
    print("Database tables created!")

if __name__ == '__main__':
    app.run(debug=True)
