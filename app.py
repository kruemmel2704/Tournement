import os
import random
import json
import math
from werkzeug.utils import secure_filename 
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
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

# --- HILFSFUNKTIONEN ---
def calculate_map_wins(scores_a, scores_b):
    wins_a = 0
    wins_b = 0
    # Gehe durch alle gespielten Maps
    for sa, sb in zip(scores_a, scores_b):
        if sa > sb: wins_a += 1
        elif sb > sa: wins_b += 1
    return wins_a, wins_b

# --- MODELLE ---

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
    is_mod = db.Column(db.Boolean, default=False)
    clan_id = db.Column(db.Integer, db.ForeignKey('clan.id'), nullable=True)
    
    # Ein Team hat mehrere Member (Spieler)
    team_members = db.relationship('Member', backref='team', lazy=True, cascade="all, delete-orphan")

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    gamertag = db.Column(db.String(100), nullable=False)
    activision_id = db.Column(db.String(100), nullable=False) # Name#12345
    platform = db.Column(db.String(50), nullable=False)

class Map(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    image_file = db.Column(db.String(120), nullable=False, default='default.jpg')
    is_archived = db.Column(db.Boolean, default=False)

# --- TURNIER (K.O. System + Ban/Pick) ---
class Tournament(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_archived = db.Column(db.Boolean, default=False)
    matches = db.relationship('Match', backref='tournament', lazy=True, cascade="all, delete-orphan")

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'))
    team_a = db.Column(db.String(100), nullable=False, default="TBD")
    team_b = db.Column(db.String(100), nullable=False, default="TBD")
    state = db.Column(db.String(50), default='waiting') 
    lobby_code = db.Column(db.String(50), nullable=True)
    
    round_number = db.Column(db.Integer, default=1)
    match_index = db.Column(db.Integer, default=0)
    next_match_id = db.Column(db.Integer, nullable=True)
    
    banned_maps = db.Column(db.Text, default='[]') 
    picked_maps = db.Column(db.Text, default='[]')
    scores_a = db.Column(db.Text, default='[]')
    scores_b = db.Column(db.Text, default='[]')
    draft_a_scores = db.Column(db.Text, nullable=True)
    draft_b_scores = db.Column(db.Text, nullable=True)
    
    chat_messages = db.relationship('ChatMessage', backref='match', lazy=True, cascade="all, delete-orphan")

    def _safe_load(self, data):
        if not data: return []
        try: return json.loads(data)
        except: return []
    def get_banned(self): return self._safe_load(self.banned_maps)
    def get_picked(self): return self._safe_load(self.picked_maps)
    def get_scores_a(self): return self._safe_load(self.scores_a)
    def get_scores_b(self): return self._safe_load(self.scores_b)
    
    # HIER FEHLTE DIE METHODE:
    def get_map_wins(self):
        return calculate_map_wins(self.get_scores_a(), self.get_scores_b())

    @property
    def total_score_a(self): return sum(self.get_scores_a())
    @property
    def total_score_b(self): return sum(self.get_scores_b())

# --- CUP (Round Robin + Einfaches Picken) ---
class Cup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_archived = db.Column(db.Boolean, default=False)
    participants = db.Column(db.Text, default='[]')
    matches = db.relationship('CupMatch', backref='cup', lazy=True, cascade="all, delete-orphan")
    def get_participants(self): return json.loads(self.participants)

class CupMatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cup_id = db.Column(db.Integer, db.ForeignKey('cup.id'), nullable=False)
    team_a = db.Column(db.String(100), nullable=False)
    team_b = db.Column(db.String(100), nullable=False)
    round_number = db.Column(db.Integer, default=1)
    
    state = db.Column(db.String(50), default='waiting_for_ready')
    ready_a = db.Column(db.Boolean, default=False)
    ready_b = db.Column(db.Boolean, default=False)
    picked_maps = db.Column(db.Text, default='[]')
    current_picker = db.Column(db.String(100), nullable=True)
    lobby_code = db.Column(db.String(50), nullable=True)
    scores_a = db.Column(db.Text, default='[]')
    scores_b = db.Column(db.Text, default='[]')
    
    chat_messages = db.relationship('CupChatMessage', backref='cup_match', lazy=True, cascade="all, delete-orphan")

    def get_picked(self): return json.loads(self.picked_maps)
    def get_scores_a(self): return json.loads(self.scores_a)
    def get_scores_b(self): return json.loads(self.scores_b)
    def get_map_wins(self):
        return calculate_map_wins(self.get_scores_a(), self.get_scores_b())

# --- LIGA (Round Robin + Ban/Pick + Double Opt-In Lineup) ---
class League(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_archived = db.Column(db.Boolean, default=False)
    participants = db.Column(db.Text, default='[]')
    matches = db.relationship('LeagueMatch', backref='league', lazy=True, cascade="all, delete-orphan")
    def get_participants(self): return json.loads(self.participants)

class LeagueMatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    league_id = db.Column(db.Integer, db.ForeignKey('league.id'), nullable=False)
    team_a = db.Column(db.String(100), nullable=False)
    team_b = db.Column(db.String(100), nullable=False)
    round_number = db.Column(db.Integer, default=1)
    
    # State Logik: ban_x -> pick_x -> scoring_phase -> confirming -> finished
    state = db.Column(db.String(50), default='ban_1_a') 
    lobby_code = db.Column(db.String(50), nullable=True)
    
    banned_maps = db.Column(db.Text, default='[]') 
    picked_maps = db.Column(db.Text, default='[]')
    
    # Finale Werte (nach Bestätigung)
    scores_a = db.Column(db.Text, default='[]')
    scores_b = db.Column(db.Text, default='[]')
    lineup_a = db.Column(db.Text, default='[]') 
    lineup_b = db.Column(db.Text, default='[]')
    
    # Draft Werte (während der Eingabe)
    draft_a_scores = db.Column(db.Text, nullable=True)
    draft_b_scores = db.Column(db.Text, nullable=True)
    
    draft_a_lineup = db.Column(db.Text, nullable=True) # Wer hat gespielt?
    draft_b_lineup = db.Column(db.Text, nullable=True)
    
    # Bestätigungs-Häkchen für Phase 2
    confirmed_a = db.Column(db.Boolean, default=False)
    confirmed_b = db.Column(db.Boolean, default=False)

    chat_messages = db.relationship('LeagueChatMessage', backref='league_match', lazy=True, cascade="all, delete-orphan")

    def _safe_load(self, data):
        if not data: return []
        try: return json.loads(data)
        except: return []
    def get_banned(self): return self._safe_load(self.banned_maps)
    def get_picked(self): return self._safe_load(self.picked_maps)
    def get_scores_a(self): return self._safe_load(self.scores_a)
    def get_scores_b(self): return self._safe_load(self.scores_b)
    
    def get_lineup_a(self): return self._safe_load(self.lineup_a)
    def get_lineup_b(self): return self._safe_load(self.lineup_b)
    
    # Helper um die Drafts anzuzeigen (Gegner Check)
    def get_draft_a_lineup(self): return self._safe_load(self.draft_a_lineup)
    def get_draft_b_lineup(self): return self._safe_load(self.draft_b_lineup)

    def get_map_wins(self):
        return calculate_map_wins(self.get_scores_a(), self.get_scores_b())

# --- CHAT MODELS ---
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey('match.id'), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    is_admin = db.Column(db.Boolean, default=False)
    is_mod = db.Column(db.Boolean, default=False)

class CupChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cup_match_id = db.Column(db.Integer, db.ForeignKey('cup_match.id'), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    is_admin = db.Column(db.Boolean, default=False)
    is_mod = db.Column(db.Boolean, default=False)

class LeagueChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    league_match_id = db.Column(db.Integer, db.ForeignKey('league_match.id'), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    is_admin = db.Column(db.Boolean, default=False)
    is_mod = db.Column(db.Boolean, default=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_initial_admin():
    try:
        admin = User.query.filter_by(username='admin').first()
        if admin: print("Admin existiert bereits.")
        else:
            hashed_pw = generate_password_hash("admin123", method='pbkdf2:sha256')
            new_admin = User(username="admin", password=hashed_pw, is_admin=True)
            db.session.add(new_admin); db.session.commit()
            print("Initialer Admin erstellt.")
    except Exception as e: print(f"Fehler Admin: {e}")

def clan_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'clan_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- SHARED LOGIK ---
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
    # Nur für Turnier-Matches (Match Klasse)
    if not match.next_match_id: return
    nm = Match.query.get(match.next_match_id)
    if not nm: return
    
    # HIER DIE KORREKTUR: Map Wins statt Score
    wa, wb = match.get_map_wins()
    if wa > wb: win = match.team_a
    elif wb > wa: win = match.team_b
    else: win = match.team_a if match.total_score_a > match.total_score_b else match.team_b

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
    
    # Lineup abrufen (nur relevant für LeagueMatch)
    lineup_list = form_data.getlist('lineup_member') 
    
    # ADMIN / MOD OVERRIDE
    if user.is_admin or user.is_mod:
        match.scores_a = json.dumps(sa); match.scores_b = json.dumps(sb)
        match.state = 'finished'; match.draft_a_scores=None; match.draft_b_scores=None
        if isinstance(match, Match): advance_winner(match)
        return True, "Admin/Mod Finish."
        
    isa = (user.username == match.team_a); isb = (user.username == match.team_b)
    if not (isa or isb): return False, "Nicht erlaubt."
    
    # DRAFT SPEICHERN
    if isa: 
        match.draft_a_scores = json.dumps(bundle)
        if isinstance(match, LeagueMatch): match.draft_a_lineup = json.dumps(lineup_list)
    elif isb: 
        match.draft_b_scores = json.dumps(bundle)
        if isinstance(match, LeagueMatch): match.draft_b_lineup = json.dumps(lineup_list)
    
    # VERGLEICH
    if match.draft_a_scores and match.draft_b_scores:
        if match.draft_a_scores == match.draft_b_scores:
            # Scores stimmen überein
            match.scores_a = json.dumps(sa); match.scores_b = json.dumps(sb)
            
            if isinstance(match, LeagueMatch):
                # Liga: Gehe zu CONFIRMATION Phase (Double Opt-In für Lineups)
                match.state = 'confirming'
                return True, "Ergebnisse stimmen. Bitte Line-up des Gegners prüfen."
            else:
                # Turnier: Direkt fertig
                match.state = 'finished'
                if isinstance(match, Match): advance_winner(match)
                return True, "Match Fertig!"
        else:
            match.state = 'conflict'; return False, "Konflikt! Ergebnisse ungleich."
    else:
        match.state = 'waiting_for_confirmation'; return True, "Gespeichert. Warte auf Gegner."


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
        
        user = User.query.filter_by(username=username).first()
        if user:
            if user.is_admin or user.is_mod:
                if user.password and check_password_hash(user.password, password):
                    login_user(user); return redirect(url_for('dashboard'))
            else:
                if user.token == password:
                    login_user(user); return redirect(url_for('dashboard'))
        
        clan = Clan.query.filter_by(name=username).first()
        if clan and check_password_hash(clan.password, password):
            session['clan_id'] = clan.id
            flash(f'Willkommen {clan.name}!', 'success')
            return redirect(url_for('clan_dashboard'))

        flash('Login fehlgeschlagen.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    session.pop('clan_id', None)
    return redirect(url_for('login'))

@app.route('/register_clan', methods=['GET', 'POST'])
def register_clan():
    if current_user.is_authenticated or 'clan_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('clan_name')
        pw = request.form.get('password')
        if not name or not pw: flash('Felder fehlen.', 'error'); return render_template('register_clan.html')
        if Clan.query.filter_by(name=name).first(): flash('Name vergeben.', 'error'); return render_template('register_clan.html')
        db.session.add(Clan(name=name, password=generate_password_hash(pw, method='pbkdf2:sha256')))
        db.session.commit(); flash('Registriert!', 'success'); return redirect(url_for('login'))
    return render_template('register_clan.html')

# --- DASHBOARD & MEMBER MANAGEMENT ---

@app.route('/dashboard')
@login_required
def dashboard():
    all_tournaments = Tournament.query.all()
    # Separate Listen für Aktiv und Archiv
    active_tournaments = [t for t in all_tournaments if not t.is_archived]
    archived_tournaments = [t for t in all_tournaments if t.is_archived]
    
    # NEU: Auch Cups & Ligen filtern/laden
    active_cups = Cup.query.filter_by(is_archived=False).all()
    archived_cups = Cup.query.filter_by(is_archived=True).all()
    active_leagues = League.query.filter_by(is_archived=False).all()
    archived_leagues = League.query.filter_by(is_archived=True).all()

    # Filter archivierte Maps aus dem Dashboard, falls nötig, oder hier alle anzeigen
    # Im Match-View ist der Filter wichtiger.
    maps = Map.query.all() 
    users = User.query.filter_by(is_admin=False).all()
    clans = Clan.query.all()
    
    users_with_clan = User.query.filter(User.clan_id != None).all()
    clan_map = {u.username: u.clan.name for u in users_with_clan}

    return render_template('dashboard.html', 
                           active_tournaments=active_tournaments, 
                           archived_tournaments=archived_tournaments,
                           active_cups=active_cups,
                           archived_cups=archived_cups, 
                           active_leagues=active_leagues,
                           archived_leagues=archived_leagues, 
                           maps=maps, users=users, clans=clans,
                           clan_map=clan_map)

@app.route('/add_member', methods=['POST'])
@login_required
def add_member():
    gamertag = request.form.get('gamertag')
    activision = request.form.get('activision_id')
    platform = request.form.get('platform')
    if not gamertag or not activision:
        flash('Bitte Gamertag und Activision ID angeben.', 'error')
    else:
        new_member = Member(user_id=current_user.id, gamertag=gamertag, activision_id=activision, platform=platform)
        db.session.add(new_member)
        db.session.commit()
        flash('Mitglied hinzugefügt!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_member/<int:member_id>', methods=['POST'])
@login_required
def delete_member(member_id):
    member = Member.query.get_or_404(member_id)
    if member.user_id != current_user.id and not current_user.is_admin:
        flash('Keine Berechtigung.', 'error')
    else:
        db.session.delete(member)
        db.session.commit()
        flash('Mitglied entfernt.', 'success')
    return redirect(url_for('dashboard'))

# --- ADMIN / USERS ---

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
    users_no_clan = User.query.filter_by(clan_id=None, is_admin=False, is_mod=False).all()
    moderators = User.query.filter_by(is_mod=True).all()
    return render_template('users.html', clans=clans, users_no_clan=users_no_clan, moderators=moderators)

# --- CLAN LOGIK ---
@app.route('/clan_dashboard')
@clan_required
def clan_dashboard():
    clan = Clan.query.get(session['clan_id'])
    free_agents = User.query.filter(User.clan_id == None, User.is_admin == False, User.is_mod == False).all()
    return render_template('clan_dashboard.html', clan=clan, free_agents=free_agents)

@app.route('/clan_add_member/<int:user_id>', methods=['POST'])
@clan_required
def clan_add_member(user_id):
    clan = Clan.query.get(session['clan_id'])
    user = User.query.get_or_404(user_id)
    if user.clan_id is None:
        user.clan_id = clan.id; db.session.commit(); flash(f'{user.username} hinzugefügt!', 'success')
    return redirect(url_for('clan_dashboard'))

@app.route('/clan_remove_member/<int:user_id>', methods=['POST'])
@clan_required
def clan_remove_member(user_id):
    clan = Clan.query.get(session['clan_id'])
    user = User.query.get_or_404(user_id)
    if user.clan_id == clan.id:
        user.clan_id = None; db.session.commit(); flash(f'{user.username} entfernt.', 'info')
    return redirect(url_for('clan_dashboard'))

@app.route('/clan_change_password', methods=['POST'])
@clan_required
def clan_change_password():
    clan = Clan.query.get(session['clan_id'])
    if not check_password_hash(clan.password, request.form.get('current_password')):
        flash('Falsches PW.', 'error'); return redirect(url_for('clan_dashboard'))
    if request.form.get('new_password') != request.form.get('confirm_password'):
        flash('PW stimmen nicht überein.', 'error'); return redirect(url_for('clan_dashboard'))
    clan.password = generate_password_hash(request.form.get('new_password'), method='pbkdf2:sha256')
    db.session.commit(); flash('PW geändert.', 'success')
    return redirect(url_for('clan_dashboard'))

@app.route('/clan_create_team', methods=['POST'])
@clan_required
def clan_create_team():
    clan = Clan.query.get(session['clan_id'])
    raw_name = request.form.get('team_name')
    if not raw_name: flash('Name eingeben.', 'error'); return redirect(url_for('clan_dashboard'))
    final_username = f"{clan.name}.{raw_name}"
    if User.query.filter_by(username=final_username).first(): flash('Name vergeben.', 'error')
    else:
        token = str(random.randint(10000, 99999))
        db.session.add(User(username=final_username, token=token, clan_id=clan.id))
        db.session.commit(); flash(f'Team {final_username} erstellt!', 'success')
    return redirect(url_for('clan_dashboard'))

# --- ADMIN ACTIONS ---

@app.route('/create_admin', methods=['POST'])
@login_required
def create_admin():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    username = request.form.get('username'); password = request.form.get('password')
    if not username or not password: flash('Felder fehlen.', 'error'); return redirect(url_for('users_manager'))
    if User.query.filter_by(username=username).first(): flash('Name existiert.', 'error')
    else:
        db.session.add(User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'), is_admin=True))
        db.session.commit(); flash(f'Admin {username} erstellt.', 'success')
    return redirect(url_for('users_manager'))

@app.route('/create_mod', methods=['POST'])
@login_required
def create_mod():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    username = request.form.get('username'); password = request.form.get('password')
    if not username or not password: flash('Felder fehlen.', 'error'); return redirect(url_for('users_manager'))
    if User.query.filter_by(username=username).first(): flash('Name existiert.', 'error')
    else:
        db.session.add(User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'), is_mod=True))
        db.session.commit(); flash(f'Mod {username} erstellt.', 'success')
    return redirect(url_for('users_manager'))

@app.route('/create_clan', methods=['POST'])
@login_required
def create_clan():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    name = request.form.get('clan_name')
    if Clan.query.filter_by(name=name).first(): flash('Name existiert.', 'error')
    else:
        db.session.add(Clan(name=name, password=generate_password_hash("1234", method='pbkdf2:sha256')))
        db.session.commit(); flash(f'Clan {name} erstellt.', 'success')
    return redirect(url_for('users_manager'))

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    raw_name = request.form.get('username'); clan_id = request.form.get('clan_id')
    if not raw_name: flash('Name fehlt.', 'error'); return redirect(url_for('users_manager'))
    final_username = raw_name
    if clan_id:
        clan = Clan.query.get(clan_id)
        if clan: final_username = f"{clan.name}.{raw_name}"
    if User.query.filter_by(username=final_username).first(): flash('Name vergeben.', 'error')
    else:
        new_user = User(username=final_username, token=str(random.randint(10000, 99999)))
        if clan_id: new_user.clan_id = clan_id
        db.session.add(new_user); db.session.commit(); flash(f'Team {final_username} erstellt.', 'success')
    return redirect(url_for('users_manager'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.delete(User.query.get_or_404(user_id)); db.session.commit()
    return redirect(url_for('users_manager'))

@app.route('/delete_clan/<int:clan_id>', methods=['POST'])
@login_required
def delete_clan(clan_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.delete(Clan.query.get_or_404(clan_id)); db.session.commit()
    return redirect(url_for('users_manager'))

@app.route('/admin_change_password', methods=['POST'])
@login_required
def admin_change_password():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    if request.form.get('new_password') == request.form.get('confirm_password'):
        current_user.password = generate_password_hash(request.form.get('new_password'), method='pbkdf2:sha256')
        db.session.commit(); flash('PW geändert.', 'success')
    return redirect(url_for('users_manager'))

@app.route('/admin_reset_clan_password/<int:clan_id>', methods=['POST'])
@login_required
def admin_reset_clan_password(clan_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    c = Clan.query.get_or_404(clan_id)
    if request.form.get('new_password'):
        c.password = generate_password_hash(request.form.get('new_password'), method='pbkdf2:sha256')
        db.session.commit(); flash('Clan PW geändert.', 'success')
    return redirect(url_for('users_manager'))

@app.route('/add_map', methods=['POST'])
@login_required
def add_map():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    files = request.files.getlist('map_images')
    for file in files:
        if file and allowed_file(file.filename):
            sname = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], sname))
            name = os.path.splitext(file.filename)[0].replace('_',' ').title()
            if not Map.query.filter_by(name=name).first(): db.session.add(Map(name=name, image_file=sname))
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
    db.session.delete(Map.query.get_or_404(map_id)); db.session.commit()
    return redirect(url_for('maps_manager'))


# --- TURNIER LOGIK ---
@app.route('/create_tournament', methods=['GET', 'POST'])
@login_required
def create_tournament():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        selected = request.form.getlist('selected_users')
        if len(selected) < 2 or len(selected) % 2 != 0: 
            flash('Ungültige Anzahl.', 'error'); return redirect(url_for('create_tournament'))
        random.shuffle(selected)
        t = Tournament(name=request.form.get('tournament_name')); db.session.add(t); db.session.commit()
        matches_r1 = []
        for i in range(0, len(selected), 2):
            m = Match(tournament_id=t.id, team_a=selected[i], team_b=selected[i+1], state='ban_1_a', round_number=1, match_index=i//2)
            db.session.add(m); matches_r1.append(m)
        db.session.commit()
        prev = matches_r1
        rounds = int(math.ceil(math.log2(len(selected))))
        for r in range(2, rounds+1):
            curr = []
            count = len(prev)//2 + (1 if len(prev)%2!=0 else 0)
            for i in range(count):
                m = Match(tournament_id=t.id, team_a="TBD", team_b="TBD", state='waiting', round_number=r, match_index=i)
                db.session.add(m); curr.append(m)
            db.session.commit()
            for idx, pm in enumerate(prev): pm.next_match_id = curr[idx//2].id
            db.session.commit(); prev = curr
        flash('Turnier erstellt!', 'success'); return redirect(url_for('dashboard'))
    return render_template('create_tournament.html', users=User.query.filter_by(is_admin=False, is_mod=False).all())

@app.route('/match/<int:match_id>', methods=['GET', 'POST'])
@login_required
def match_view(match_id):
    match = Match.query.get_or_404(match_id)
    active_team = None
    if match.state.endswith('_a'): active_team = match.team_a
    elif match.state.endswith('_b'): active_team = match.team_b

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
        # LOBBY CODE FÜR TURNIERE
        elif 'lobby_code' in request.form and (current_user.is_admin or current_user.is_mod):
            match.lobby_code = request.form.get('lobby_code'); db.session.commit()
            
        return redirect(url_for('match_view', match_id=match.id))

    # KORREKTUR: Filter archivierte Maps
    return render_template('match.html', match=match, all_maps=Map.query.filter_by(is_archived=False).all(), banned=match.get_banned(), picked=match.get_picked(), active_team=active_team)

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
    db.session.delete(Tournament.query.get_or_404(t_id)); db.session.commit()
    return redirect(url_for('dashboard'))

# --- CUP LOGIK ---

@app.route('/create_cup', methods=['GET', 'POST'])
@login_required
def create_cup():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('cup_name'); teams = request.form.getlist('selected_users')
        if len(teams) < 2: flash('Min. 2 Teams.', 'error'); return redirect(url_for('create_cup'))
        c = Cup(name=name, participants=json.dumps(teams)); db.session.add(c); db.session.commit()
        if len(teams) % 2 != 0: teams.append(None)
        num_teams = len(teams); num_rounds = num_teams - 1; matches_per_round = num_teams // 2
        for r in range(num_rounds):
            for i in range(matches_per_round):
                t1, t2 = teams[i], teams[num_teams - 1 - i]
                if t1 and t2: db.session.add(CupMatch(cup_id=c.id, team_a=t1, team_b=t2, current_picker=t1, round_number=r+1))
            teams.insert(1, teams.pop())
        db.session.commit(); flash(f'Cup {name} erstellt!', 'success'); return redirect(url_for('dashboard'))
    return render_template('create_cup.html', users=User.query.filter_by(is_admin=False, is_mod=False).all())

@app.route('/cup/<int:cup_id>')
@login_required
def cup_details(cup_id):
    cup = Cup.query.get_or_404(cup_id)
    standings = {user: {'played': 0, 'won_matches': 0, 'lost_matches': 0, 'draw_matches': 0, 'own_score': 0, 'opp_score': 0} for user in cup.get_participants()}
    for m in cup.matches:
        if m.state == 'finished':
            wa, wb = m.get_map_wins() # HIER NEU
            sum_a = sum(m.get_scores_a()); sum_b = sum(m.get_scores_b())
            if m.team_a in standings:
                s = standings[m.team_a]; s['played']+=1; s['own_score']+=sum_a; s['opp_score']+=sum_b
                if wa>wb: s['won_matches']+=1
                elif wb>wa: s['lost_matches']+=1
                else: s['draw_matches']+=1
            if m.team_b in standings:
                s = standings[m.team_b]; s['played']+=1; s['own_score']+=sum_b; s['opp_score']+=sum_a
                if wb>wa: s['won_matches']+=1
                elif wa>wb: s['lost_matches']+=1
                else: s['draw_matches']+=1
    return render_template('cup_details.html', cup=cup, standings=sorted(standings.items(), key=lambda x: x[1]['own_score'], reverse=True))

@app.route('/cup_match/<int:match_id>', methods=['GET', 'POST'])
@login_required
def cup_match_view(match_id):
    match = CupMatch.query.get_or_404(match_id)
    if not (current_user.is_admin or current_user.is_mod or current_user.username in [match.team_a, match.team_b]):
        flash("Kein Zugriff.", "error"); return redirect(url_for('dashboard'))
    if request.method == 'POST':
        # NEU: ADMIN 3-MAP SETTING
        if 'set_maps' in request.form and (current_user.is_admin or current_user.is_mod):
            # Hole 3 Maps
            selected = [request.form.get(f'map_{i}') for i in range(1, 4)]
            match.picked_maps = json.dumps(selected)
            match.state = 'waiting_for_code'
            db.session.commit()
        elif 'set_lobby_code' in request.form and (current_user.is_admin or current_user.is_mod):
            match.lobby_code = request.form.get('lobby_code')
            match.state = 'in_progress'
            db.session.commit()
        elif 'submit_scores' in request.form and (current_user.is_admin or current_user.is_mod):
            try:
                # 3 SCORES
                sa = [int(request.form.get(f'score_a_{i}', 0)) for i in range(3)]
                sb = [int(request.form.get(f'score_b_{i}', 0)) for i in range(3)]
                match.scores_a = json.dumps(sa); match.scores_b = json.dumps(sb); match.state = 'finished'
                db.session.commit(); flash("Gespeichert.", "success")
            except: flash("Fehler.", "error")
        return redirect(url_for('cup_match_view', match_id=match.id))
    # KORREKTUR: Filter archivierte Maps
    return render_template('cup_match.html', match=match, all_maps=Map.query.filter_by(is_archived=False).all(), picked=match.get_picked())

# --- NEU: CUP ARCHIV ---
@app.route('/archive_cup/<int:cup_id>', methods=['POST'])
@login_required
def archive_cup(cup_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    c = Cup.query.get_or_404(cup_id); c.is_archived = not c.is_archived; db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete_cup/<int:cup_id>', methods=['POST'])
@login_required
def delete_cup(cup_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.delete(Cup.query.get_or_404(cup_id)); db.session.commit()
    return redirect(url_for('dashboard'))

# --- LIGA LOGIK (Round Robin + Ban/Pick + Confirmation) ---

@app.route('/create_league', methods=['GET', 'POST'])
@login_required
def create_league():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('league_name'); teams = request.form.getlist('selected_users')
        if len(teams) < 2: flash('Min. 2 Teams.', 'error'); return redirect(url_for('create_league'))
        l = League(name=name, participants=json.dumps(teams)); db.session.add(l); db.session.commit()
        if len(teams) % 2 != 0: teams.append(None)
        num_teams = len(teams); num_rounds = num_teams - 1; matches_per_round = num_teams // 2
        for r in range(num_rounds):
            for i in range(matches_per_round):
                t1, t2 = teams[i], teams[num_teams - 1 - i]
                if t1 and t2: db.session.add(LeagueMatch(league_id=l.id, team_a=t1, team_b=t2, round_number=r+1, state='ban_1_a'))
            teams.insert(1, teams.pop())
        db.session.commit(); flash(f'Liga {name} erstellt!', 'success'); return redirect(url_for('dashboard'))
    return render_template('create_league.html', users=User.query.filter_by(is_admin=False, is_mod=False).all())

@app.route('/league/<int:league_id>')
def league_details(league_id):
    league = League.query.get_or_404(league_id)
    standings = {user: {'played': 0, 'won_matches': 0, 'lost_matches': 0, 'draw_matches': 0, 'own_score': 0, 'opp_score': 0} for user in league.get_participants()}
    for m in league.matches:
        if m.state == 'finished':
            wa, wb = m.get_map_wins(); sum_a = sum(m.get_scores_a()); sum_b = sum(m.get_scores_b())
            if m.team_a in standings:
                standings[m.team_a]['played'] += 1; standings[m.team_a]['own_score'] += sum_a; standings[m.team_a]['opp_score'] += sum_b
                if wa > wb: standings[m.team_a]['won_matches'] += 1
                elif wb > wa: standings[m.team_a]['lost_matches'] += 1
                else: standings[m.team_a]['draw_matches'] += 1
            if m.team_b in standings:
                standings[m.team_b]['played'] += 1; standings[m.team_b]['own_score'] += sum_b; standings[m.team_b]['opp_score'] += sum_a
                if wb > wa: standings[m.team_b]['won_matches'] += 1
                elif wa > wb: standings[m.team_b]['lost_matches'] += 1
                else: standings[m.team_b]['draw_matches'] += 1
    return render_template('league_details.html', league=league, standings=sorted(standings.items(), key=lambda x: x[1]['own_score'], reverse=True))

@app.route('/league_match/<int:match_id>', methods=['GET', 'POST'])
@login_required
def league_match_view(match_id):
    match = LeagueMatch.query.get_or_404(match_id)
    active_team = None
    if match.state.endswith('_a'): active_team = match.team_a
    elif match.state.endswith('_b'): active_team = match.team_b
    if not (current_user.is_admin or current_user.is_mod or current_user.username in [match.team_a, match.team_b]):
        flash("Kein Zugriff.", "error"); return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # 1. Ban/Pick
        if 'selected_map' in request.form:
            if current_user.is_admin or current_user.username == active_team:
                s, m = handle_pick_ban_logic(match, request.form.get('selected_map'))
                db.session.commit()
                if not s: flash(m, "error")
            else: flash("Nicht an der Reihe.", "error")
        
        # 2. Submit Scores & Lineup
        elif 'submit_scores' in request.form:
            s, m = handle_scoring_logic(match, request.form, current_user)
            db.session.commit(); flash(m, "success" if s else "error")
        
        # 3. Confirmation (Phase 2)
        elif 'confirm_lineup' in request.form:
            if current_user.username == match.team_a: match.confirmed_a = True
            elif current_user.username == match.team_b: match.confirmed_b = True
            
            if match.confirmed_a and match.confirmed_b:
                match.state = 'finished'
                # Draft Lineups übernehmen
                match.lineup_a = match.draft_a_lineup
                match.lineup_b = match.draft_b_lineup
                flash("Match beendet!", "success")
            else:
                flash("Bestätigt. Warte auf Gegner...", "info")
            db.session.commit()

        # 4. Lobby Code
        elif 'lobby_code' in request.form and (current_user.is_admin or current_user.is_mod):
             match.lobby_code = request.form.get('lobby_code')
             db.session.commit()
        return redirect(url_for('league_match_view', match_id=match.id))
    # KORREKTUR: Filter archivierte Maps
    return render_template('league_match.html', match=match, all_maps=Map.query.filter_by(is_archived=False).all(), banned=match.get_banned(), picked=match.get_picked(), active_team=active_team)

# --- NEU: LIGA ARCHIV ---
@app.route('/archive_league/<int:league_id>', methods=['POST'])
@login_required
def archive_league(league_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    l = League.query.get_or_404(league_id); l.is_archived = not l.is_archived; db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete_league/<int:league_id>', methods=['POST'])
@login_required
def delete_league(league_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.delete(League.query.get_or_404(league_id)); db.session.commit()
    return redirect(url_for('dashboard'))

# --- APIs für LIVE UPDATE ---

@app.route('/api/match/<int:match_id>/chat', methods=['GET', 'POST'])
@login_required
def match_chat_api(match_id):
    try:
        match = Match.query.get_or_404(match_id)
        if request.method == 'POST':
            data = request.json
            if data.get('message'):
                db.session.add(ChatMessage(match_id=match.id, username=current_user.username, message=data['message'], is_admin=current_user.is_admin, is_mod=current_user.is_mod))
                db.session.commit(); return json.dumps({'status': 'ok'}), 200
        msgs = ChatMessage.query.filter_by(match_id=match_id).order_by(ChatMessage.timestamp).all()
        return json.dumps([{'user': m.username, 'text': m.message, 'time': m.timestamp.strftime('%H:%M'), 'is_admin': m.is_admin, 'is_mod': m.is_mod, 'is_me': m.username == current_user.username} for m in msgs]), 200
    except Exception as e: return json.dumps({'error': str(e)}), 500

@app.route('/api/match/<int:match_id>/lobby_code', methods=['GET', 'POST'])
@login_required
def lobby_code_api(match_id):
    match = Match.query.get_or_404(match_id)
    if request.method == 'GET': return json.dumps({'lobby_code': match.lobby_code or ''}), 200
    if current_user.is_admin or current_user.is_mod or current_user.username in [match.team_a, match.team_b]:
        match.lobby_code = request.json.get('lobby_code', '').strip(); db.session.commit(); return json.dumps({'status': 'ok'}), 200
    return json.dumps({'status': 'error'}), 403

@app.route('/api/cup_match/<int:match_id>/state')
@login_required
def cup_match_state(match_id):
    match = CupMatch.query.get_or_404(match_id)
    return json.dumps({'state': match.state, 'current_picker': match.current_picker, 'picked': match.get_picked(), 'lobby_code': match.lobby_code, 'ready_a': match.ready_a, 'ready_b': match.ready_b})

@app.route('/api/cup_match/<int:match_id>/chat', methods=['GET', 'POST'])
@login_required
def cup_chat_api(match_id):
    try:
        match = CupMatch.query.get_or_404(match_id)
        if request.method == 'POST':
            data = request.json
            if data.get('message'):
                db.session.add(CupChatMessage(cup_match_id=match.id, username=current_user.username, message=data['message'], is_admin=current_user.is_admin, is_mod=current_user.is_mod))
                db.session.commit(); return json.dumps({'status': 'ok'}), 200
        msgs = CupChatMessage.query.filter_by(cup_match_id=match_id).order_by(CupChatMessage.timestamp).all()
        return json.dumps([{'user': m.username, 'text': m.message, 'time': m.timestamp.strftime('%H:%M'), 'is_admin': m.is_admin, 'is_mod': m.is_mod, 'is_me': m.username == current_user.username} for m in msgs]), 200
    except Exception as e: return json.dumps({'error': str(e)}), 500

@app.route('/api/league_match/<int:match_id>/chat', methods=['GET', 'POST'])
@login_required
def league_match_chat_api(match_id):
    try:
        match = LeagueMatch.query.get_or_404(match_id)
        if request.method == 'POST':
            data = request.json
            if data.get('message'):
                db.session.add(LeagueChatMessage(league_match_id=match.id, username=current_user.username, message=data['message'], is_admin=current_user.is_admin, is_mod=current_user.is_mod))
                db.session.commit(); return json.dumps({'status': 'ok'}), 200
        msgs = LeagueChatMessage.query.filter_by(league_match_id=match_id).order_by(LeagueChatMessage.timestamp).all()
        return json.dumps([{'user': m.username, 'text': m.message, 'time': m.timestamp.strftime('%H:%M'), 'is_admin': m.is_admin, 'is_mod': m.is_mod, 'is_me': m.username == current_user.username} for m in msgs]), 200
    except Exception as e: return json.dumps({'error': str(e)}), 500

@app.route('/api/league_match/<int:match_id>/lobby_code', methods=['GET'])
@login_required
def league_lobby_code_api(match_id):
    match = LeagueMatch.query.get_or_404(match_id)
    return json.dumps({'lobby_code': match.lobby_code or ''}), 200

@app.route('/api/league_match/<int:match_id>/state')
@login_required
def league_match_state(match_id):
    match = LeagueMatch.query.get_or_404(match_id)
    active_team = None
    if match.state.endswith('_a'): active_team = match.team_a
    elif match.state.endswith('_b'): active_team = match.team_b
    return json.dumps({
        'state': match.state, 'active_team': active_team,
        'banned': match.get_banned(), 'picked': match.get_picked(),
        'lobby_code': match.lobby_code, 'confirmed_a': match.confirmed_a, 'confirmed_b': match.confirmed_b
    })

@app.route('/rules')
def rules(): return render_template('rules.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_initial_admin()
    app.run(debug=True, host='0.0.0.0')