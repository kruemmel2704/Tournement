import os
import random
import json
import math
from werkzeug.utils import secure_filename 
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps 
from datetime import datetime

# --- Konfiguration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dein-geheimer-schluessel-bitte-aendern' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tournament.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/map_images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- NEUE MODELLE ---

class Clan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    members = db.relationship('User', backref='clan', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=True) 
    token = db.Column(db.String(5), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    clan_id = db.Column(db.Integer, db.ForeignKey('clan.id'), nullable=True)

class Map(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    image_file = db.Column(db.String(120), nullable=False, default='default.jpg')
    is_archived = db.Column(db.Boolean, default=False)

class Tournament(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_archived = db.Column(db.Boolean, default=False)
    matches = db.relationship('Match', backref='tournament', lazy=True, cascade="all, delete-orphan")

class Match(db.Model):
    # ... (deine bestehenden Felder id, team_a, etc. lassen) ...
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'))
    team_a = db.Column(db.String(100), nullable=False, default="TBD")
    team_b = db.Column(db.String(100), nullable=False, default="TBD")
    state = db.Column(db.String(50), default='waiting') 
    
    # NEU: LOBBY CODE
    lobby_code = db.Column(db.String(50), nullable=True)

    # ... (Rest der Match-Felder wie round_number, scores_a, etc. lassen) ...
    round_number = db.Column(db.Integer, default=1)
    match_index = db.Column(db.Integer, default=0)
    next_match_id = db.Column(db.Integer, nullable=True)
    banned_maps = db.Column(db.Text, default='[]') 
    picked_maps = db.Column(db.Text, default='[]')
    scores_a = db.Column(db.Text, default='[]')
    scores_b = db.Column(db.Text, default='[]')
    draft_a_scores = db.Column(db.Text, nullable=True)
    draft_b_scores = db.Column(db.Text, nullable=True)

    # Beziehung zu Chat Nachrichten
    chat_messages = db.relationship('ChatMessage', backref='match', lazy=True, cascade="all, delete-orphan")

    # ... (deine bestehenden Methoden _safe_load, properties etc. lassen) ...
    def _safe_load(self, data):
        if not data: return []
        try: return json.loads(data)
        except: return []

    def get_banned(self): return self._safe_load(self.banned_maps)
    def get_picked(self): return self._safe_load(self.picked_maps)
    def get_scores_a(self): return self._safe_load(self.scores_a)
    def get_scores_b(self): return self._safe_load(self.scores_b)

    @property
    def total_score_a(self): return sum(self.get_scores_a())
    @property
    def total_score_b(self): return sum(self.get_scores_b())

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey('match.id'), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_initial_admin():
    if User.query.count() == 0:
        hashed_pw = generate_password_hash("admin123", method='pbkdf2:sha256')
        admin = User(username="admin", password=hashed_pw, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("Admin Account erstellt.")

# --- Hilfs-Decorator für Clan-Bereich ---
def clan_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'clan_id' not in session:
            flash('Bitte als Clan einloggen.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def handle_pick_ban_logic(match, selected_map):
    current_banned = match.get_banned()
    current_picked = match.get_picked()
    if selected_map in current_banned or selected_map in current_picked: return False, "Karte vergeben."
    if match.state == 'ban_1_a':
        current_banned.append(selected_map); 
        if len(current_banned) >= 2: match.state = 'ban_1_b'
    elif match.state == 'ban_1_b':
        current_banned.append(selected_map); 
        if len(current_banned) >= 4: match.state = 'ban_2_a'
    elif match.state == 'ban_2_a':
        current_banned.append(selected_map); 
        if len(current_banned) >= 6: match.state = 'ban_2_b'
    elif match.state == 'ban_2_b':
        current_banned.append(selected_map); 
        if len(current_banned) >= 8: match.state = 'pick_a'
    elif match.state == 'pick_a':
        current_picked.append(selected_map); 
        if len(current_picked) >= 2: match.state = 'pick_b'
    elif match.state == 'pick_b':
        current_picked.append(selected_map); 
        if len(current_picked) >= 4: match.state = 'scoring_phase'
    match.banned_maps = json.dumps(current_banned)
    match.picked_maps = json.dumps(current_picked)
    return True, "Gespeichert."

def advance_winner(match):
    if not match.next_match_id: return
    nm = Match.query.get(match.next_match_id)
    if not nm: return
    win = match.team_a if match.total_score_a > match.total_score_b else match.team_b
    if match.total_score_a == match.total_score_b: return
    if match.match_index % 2 == 0:
        nm.team_a = win; 
        if nm.team_b != "TBD": nm.state = 'ban_1_a'
    else:
        nm.team_b = win; 
        if nm.team_a != "TBD": nm.state = 'ban_1_a'
    db.session.commit()

def handle_scoring_logic(match, form_data, user):
    pm = match.get_picked(); num = len(pm) if pm else 4
    try:
        sa = [max(0, int(form_data.get(f'score_a_{i}',0))) for i in range(1, num+1)]
        sb = [max(0, int(form_data.get(f'score_b_{i}',0))) for i in range(1, num+1)]
    except: return False, "Fehler."
    bundle = {'a':sa, 'b':sb}
    
    if user.is_admin:
        match.scores_a = json.dumps(sa); match.scores_b = json.dumps(sb)
        match.state = 'finished'; match.draft_a_scores=None; match.draft_b_scores=None
        advance_winner(match)
        return True, "Admin Finish."
        
    isa = (user.username == match.team_a); isb = (user.username == match.team_b)
    if not (isa or isb): return False, "Nicht erlaubt."
    
    if isa: match.draft_a_scores = json.dumps(bundle)
    elif isb: match.draft_b_scores = json.dumps(bundle)
    
    if match.draft_a_scores and match.draft_b_scores:
        if match.draft_a_scores == match.draft_b_scores:
            match.scores_a = json.dumps(sa); match.scores_b = json.dumps(sb)
            match.state = 'finished'; advance_winner(match)
            return True, "Match Fertig!"
        else: match.state = 'conflict'; return False, "Konflikt."
    else: match.state = 'waiting_for_confirmation'; return True, "Gespeichert."


# --- ROUTEN ---

@app.route('/')
def index():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if 'clan_id' in session: return redirect(url_for('clan_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 1. Prüfen ob es ein USER ist (Team/Admin)
        user = User.query.filter_by(username=username).first()
        if user:
            if user.is_admin:
                if user.password and check_password_hash(user.password, password):
                    login_user(user); return redirect(url_for('dashboard'))
            else:
                if user.token == password:
                    login_user(user); return redirect(url_for('dashboard'))
        
        # 2. Prüfen ob es ein CLAN ist
        clan = Clan.query.filter_by(name=username).first()
        if clan and check_password_hash(clan.password, password):
            session['clan_id'] = clan.id
            flash(f'Willkommen Clan {clan.name}!', 'success')
            return redirect(url_for('clan_dashboard'))

        flash('Login fehlgeschlagen. Prüfe Name und Passwort/Token.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    session.pop('clan_id', None)
    return redirect(url_for('login'))

# --- CLAN BEREICH ---

@app.route('/clan_dashboard')
@clan_required
def clan_dashboard():
    clan = Clan.query.get(session['clan_id'])
    free_agents = User.query.filter(User.clan_id == None, User.is_admin == False).all()
    return render_template('clan_dashboard.html', clan=clan, free_agents=free_agents)

@app.route('/clan_add_member/<int:user_id>', methods=['POST'])
@clan_required
def clan_add_member(user_id):
    clan = Clan.query.get(session['clan_id'])
    user = User.query.get_or_404(user_id)
    
    if user.clan_id is None:
        user.clan_id = clan.id
        db.session.commit()
        flash(f'{user.username} wurde zum Clan hinzugefügt!', 'success')
    else:
        flash('User ist bereits in einem anderen Clan.', 'error')
    return redirect(url_for('clan_dashboard'))

@app.route('/clan_remove_member/<int:user_id>', methods=['POST'])
@clan_required
def clan_remove_member(user_id):
    clan = Clan.query.get(session['clan_id'])
    user = User.query.get_or_404(user_id)
    
    if user.clan_id == clan.id:
        user.clan_id = None
        db.session.commit()
        flash(f'{user.username} wurde aus dem Clan entfernt.', 'info')
    return redirect(url_for('clan_dashboard'))

# --- ADMIN BEREICH: CLAN ERSTELLEN ---

@app.route('/create_clan', methods=['POST'])
@login_required
def create_clan():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    
    name = request.form.get('clan_name')
    default_pw = "1234" 
    
    if Clan.query.filter_by(name=name).first():
        flash('Clan Name existiert bereits.', 'error')
    else:
        hashed_pw = generate_password_hash(default_pw, method='pbkdf2:sha256')
        new_clan = Clan(name=name, password=hashed_pw)
        db.session.add(new_clan)
        db.session.commit()
        flash(f'Clan "{name}" erstellt! (Standard-PW: 1234)', 'success')
        
    return redirect(url_for('users_manager'))

@app.route('/dashboard')
@login_required
def dashboard():
    all_tournaments = Tournament.query.all()
    active_tournaments = [t for t in all_tournaments if not t.is_archived]
    archived_tournaments = [t for t in all_tournaments if t.is_archived]
    
    maps = Map.query.all()
    users = User.query.filter_by(is_admin=False).all()
    clans = Clan.query.all()

    users_with_clan = User.query.filter(User.clan_id != None).all()
    clan_map = {u.username: u.clan.name for u in users_with_clan}

    return render_template('dashboard.html', 
                           active_tournaments=active_tournaments, 
                           archived_tournaments=archived_tournaments,
                           maps=maps, users=users, clans=clans,
                           clan_map=clan_map) 
@app.route('/maps')
@login_required
def maps_manager():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    return render_template('maps.html', active_maps=[m for m in Map.query.all() if not m.is_archived], archived_maps=[m for m in Map.query.all() if m.is_archived])

@app.route('/users')
@login_required
def users_manager():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    
    clans = Clan.query.all()
    users_no_clan = User.query.filter_by(clan_id=None, is_admin=False).all()
    
    return render_template('users.html', clans=clans, users_no_clan=users_no_clan)


@app.route('/register_clan', methods=['GET', 'POST'])
def register_clan():
    if current_user.is_authenticated or 'clan_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('clan_name')
        pw = request.form.get('password')
        pw_confirm = request.form.get('confirm_password')

        # 1. Validierung
        if not name or not pw:
            flash('Bitte alle Felder ausfüllen.', 'error')
            return render_template('register_clan.html')
            
        if pw != pw_confirm:
            flash('Die Passwörter stimmen nicht überein.', 'error')
            return render_template('register_clan.html')

        # 2. Prüfen ob Name schon existiert
        if Clan.query.filter_by(name=name).first():
            flash('Dieser Clan-Name ist bereits vergeben.', 'error')
            return render_template('register_clan.html')
        
        # 3. Speichern (Passwort hashen!)
        hashed_pw = generate_password_hash(pw, method='pbkdf2:sha256')
        new_clan = Clan(name=name, password=hashed_pw)
        db.session.add(new_clan)
        db.session.commit()

        flash('Clan erfolgreich registriert! Bitte einloggen.', 'success')
        return redirect(url_for('login'))

    return render_template('register_clan.html')

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    
    name = request.form.get('username')
    clan_id = request.form.get('clan_id') 

    if not User.query.filter_by(username=name).first():
        token = str(random.randint(10000, 99999))
        new_user = User(username=name, token=token)
        
        if clan_id:
            new_user.clan_id = int(clan_id)
            
        db.session.add(new_user)
        db.session.commit()
        flash(f'Team "{name}" erstellt.', 'success')
    else:
        flash(f'Name "{name}" ist bereits vergeben.', 'error')
        
    return redirect(url_for('users_manager'))

# --- CLAN TEAM ERSTELLUNG ---
@app.route('/clan_create_team', methods=['POST'])
@clan_required
def clan_create_team():
    clan = Clan.query.get(session['clan_id'])
    username = request.form.get('team_name')
    
    if not username:
        flash('Bitte einen Namen eingeben.', 'error')
        return redirect(url_for('clan_dashboard'))
        
    if User.query.filter_by(username=username).first():
        flash(f'Der Name "{username}" ist leider schon vergeben.', 'error')
        return redirect(url_for('clan_dashboard'))
    
    # Token generieren
    token = str(random.randint(10000, 99999))
    
    # User erstellen und DIREKT dem Clan zuweisen (clan_id=clan.id)
    new_team = User(username=username, token=token, clan_id=clan.id)
    
    db.session.add(new_team)
    db.session.commit()
    
    flash(f'Team "{username}" erfolgreich erstellt! Token: {token}', 'success')
    return redirect(url_for('clan_dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    u = User.query.get_or_404(user_id)
    if not u.is_admin:
        db.session.delete(u)
        db.session.commit()
        flash('Team gelöscht.', 'success')
    return redirect(url_for('users_manager'))

@app.route('/delete_clan/<int:clan_id>', methods=['POST'])
@login_required
def delete_clan(clan_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    clan = Clan.query.get_or_404(clan_id)
    
    db.session.delete(clan)
    db.session.commit()
    flash(f'Clan "{clan.name}" gelöscht.', 'success')
    return redirect(url_for('users_manager'))

# --- PASSWORT MANAGEMENT ROUTEN ---

@app.route('/admin_change_password', methods=['POST'])
@login_required
def admin_change_password():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    
    new_pw = request.form.get('new_password')
    confirm_pw = request.form.get('confirm_password')
    
    if not new_pw or not confirm_pw:
        flash('Bitte Felder ausfüllen.', 'error')
    elif new_pw != confirm_pw:
        flash('Passwörter stimmen nicht überein.', 'error')
    else:
        current_user.password = generate_password_hash(new_pw, method='pbkdf2:sha256')
        db.session.commit()
        flash('Dein Admin-Passwort wurde geändert.', 'success')
        
    return redirect(url_for('users_manager'))

@app.route('/admin_reset_clan_password/<int:clan_id>', methods=['POST'])
@login_required
def admin_reset_clan_password(clan_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    
    clan = Clan.query.get_or_404(clan_id)
    new_pw = request.form.get('new_password')
    
    if new_pw:
        clan.password = generate_password_hash(new_pw, method='pbkdf2:sha256')
        db.session.commit()
        flash(f'Passwort für Clan "{clan.name}" wurde geändert.', 'success')
    else:
        flash('Passwort darf nicht leer sein.', 'error')
        
    return redirect(url_for('users_manager'))

@app.route('/clan_change_password', methods=['POST'])
@clan_required
def clan_change_password():
    clan = Clan.query.get(session['clan_id'])
    
    current_pw = request.form.get('current_password')
    new_pw = request.form.get('new_password')
    confirm_pw = request.form.get('confirm_password')
    
    # 1. Altes Passwort prüfen
    if not check_password_hash(clan.password, current_pw):
        flash('Das aktuelle Passwort ist falsch.', 'error')
        return redirect(url_for('clan_dashboard'))
    
    # 2. Neues Passwort prüfen
    if new_pw != confirm_pw:
        flash('Die neuen Passwörter stimmen nicht überein.', 'error')
        return redirect(url_for('clan_dashboard'))
        
    # 3. Speichern
    clan.password = generate_password_hash(new_pw, method='pbkdf2:sha256')
    db.session.commit()
    flash('Passwort erfolgreich geändert!', 'success')
    
    return redirect(url_for('clan_dashboard'))

@app.route('/reset_token/<int:user_id>', methods=['POST'])
@login_required
def reset_token(user_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    u = User.query.get_or_404(user_id)
    u.token = str(random.randint(10000, 99999))
    db.session.commit()
    return redirect(url_for('users_manager'))

@app.route('/add_map', methods=['POST'])
@login_required
def add_map():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    files = request.files.getlist('map_images')
    for file in files:
        if file and allowed_file(file.filename):
            name = os.path.splitext(file.filename)[0].replace('_',' ').title()
            sname = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], sname))
            if not Map.query.filter_by(name=name).first():
                db.session.add(Map(name=name, image_file=sname))
    db.session.commit()
    return redirect(url_for('maps_manager'))

@app.route('/archive_map/<int:map_id>', methods=['POST'])
@login_required
def archive_map(map_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    m = Map.query.get_or_404(map_id); m.is_archived = not m.is_archived; db.session.commit()
    return redirect(url_for('maps_manager'))

@app.route('/delete_map/<int:map_id>', methods=['POST'])
@login_required
def delete_map(map_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    m = Map.query.get_or_404(map_id); db.session.delete(m); db.session.commit()
    return redirect(url_for('maps_manager'))

@app.route('/create_tournament', methods=['GET', 'POST'])
@login_required
def create_tournament():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        t_name = request.form.get('tournament_name')
        selected = request.form.getlist('selected_users')
        num = len(selected)
        if num < 2 or num % 2 != 0: 
            flash('Ungültige Anzahl Teams.', 'error'); return render_template('create_tournament.html', users=User.query.filter_by(is_admin=False).all())
        
        random.shuffle(selected)
        t = Tournament(name=t_name); db.session.add(t); db.session.commit()
        rounds = int(math.ceil(math.log2(num)))
        matches_r1 = []
        for i in range(0, num, 2):
            m = Match(tournament_id=t.id, team_a=selected[i], team_b=selected[i+1], state='ban_1_a', round_number=1, match_index=i//2)
            db.session.add(m); matches_r1.append(m)
        db.session.commit()
        
        prev = matches_r1
        for r in range(2, rounds+1):
            curr = []
            count = len(prev)//2 + (1 if len(prev)%2!=0 else 0)
            for i in range(count):
                m = Match(tournament_id=t.id, team_a="TBD", team_b="TBD", state='waiting', round_number=r, match_index=i)
                db.session.add(m); curr.append(m)
            db.session.commit()
            for idx, pm in enumerate(prev): pm.next_match_id = curr[idx//2].id
            db.session.commit(); prev = curr
        flash('Turnier erstellt!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_tournament.html', users=User.query.filter_by(is_admin=False).order_by(User.username).all())

@app.route('/archive_tournament/<int:t_id>', methods=['POST'])
@login_required
def archive_tournament(t_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    t = Tournament.query.get_or_404(t_id); t.is_archived = not t.is_archived; db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete_tournament/<int:t_id>', methods=['POST'])
@login_required
def delete_tournament(t_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    t = Tournament.query.get_or_404(t_id); db.session.delete(t); db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/match/<int:match_id>', methods=['GET', 'POST'])
@login_required
def match_view(match_id):
    match = Match.query.get_or_404(match_id)
    active_team = None
    if match.state.endswith('_a'): active_team = match.team_a
    elif match.state.endswith('_b'): active_team = match.team_b

    if match.team_a == "TBD" or match.team_b == "TBD":
        if not current_user.is_admin:
            flash("Match steht noch nicht fest.", "info"); return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if 'selected_map' in request.form:
            if current_user.is_admin or current_user.username == active_team:
                s, m = handle_pick_ban_logic(match, request.form.get('selected_map'))
                db.session.commit(); 
                if not s: flash(m, "error")
            else: flash("Nicht an der Reihe.", "error")
        elif 'submit_scores' in request.form:
            s, m = handle_scoring_logic(match, request.form, current_user)
            db.session.commit(); flash(m, "success" if s else "error")
        return redirect(url_for('match_view', match_id=match.id))

    return render_template('match.html', match=match, all_maps=Map.query.all(), banned=match.get_banned(), picked=match.get_picked(), active_team=active_team)
@app.route('/api/match/<int:match_id>/chat', methods=['GET', 'POST'])
@login_required
def match_chat_api(match_id):
    match = Match.query.get_or_404(match_id)
    
    # Nachricht speichern
    if request.method == 'POST':
        data = request.json
        msg_text = data.get('message', '').strip()
        if msg_text:
            new_msg = ChatMessage(
                match_id=match.id,
                username=current_user.username,
                message=msg_text,
                is_admin=current_user.is_admin
            )
            db.session.add(new_msg)
            db.session.commit()
            return json.dumps({'status': 'ok'}), 200, {'ContentType': 'application/json'}
    
    # Nachrichten laden
    messages = ChatMessage.query.filter_by(match_id=match_id).order_by(ChatMessage.timestamp.asc()).all()
    msg_list = []
    for m in messages:
        msg_list.append({
            'user': m.username,
            'text': m.message,
            'time': m.timestamp.strftime('%H:%M'),
            'is_admin': m.is_admin,
            'is_me': m.username == current_user.username
        })
    
    return json.dumps(msg_list), 200, {'ContentType': 'application/json'}

@app.route('/api/match/<int:match_id>/lobby_code', methods=['GET', 'POST'])
@login_required
def lobby_code_api(match_id):
    match = Match.query.get_or_404(match_id)
    
    # --- GET: CODE ABRUFEN (Für Live-Update) ---
    if request.method == 'GET':
        # Wir geben den Code zurück (oder leeren String, falls None)
        return json.dumps({'lobby_code': match.lobby_code or ''}), 200, {'ContentType': 'application/json'}

    # --- POST: CODE SPEICHERN ---
    # Berechtigung prüfen
    is_authorized = current_user.is_admin or current_user.username in [match.team_a, match.team_b]
    if not is_authorized:
        return json.dumps({'status': 'error', 'message': 'Nicht berechtigt'}), 403

    data = request.json
    new_code = data.get('lobby_code', '').strip()
    
    match.lobby_code = new_code
    db.session.commit()
    
    return json.dumps({'status': 'ok', 'new_code': new_code}), 200

@app.route('/rules')
def rules():
    return render_template('rules.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_initial_admin()
    app.run(debug=True, host='0.0.0.0')