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

# ==========================================
# DATENBANK MODELLE
# ==========================================

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
    
    # Ein Team (User) hat mehrere echte Spieler (Members)
    team_members = db.relationship('Member', backref='team', lazy=True, cascade="all, delete-orphan")

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    gamertag = db.Column(db.String(100), nullable=False)
    activision_id = db.Column(db.String(100), nullable=False) # z.B. Name#12345
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
    
    # Draft Speicher für Konfliktlösung
    draft_a_scores = db.Column(db.Text, nullable=True)
    draft_b_scores = db.Column(db.Text, nullable=True)
    
    chat_messages = db.relationship('ChatMessage', backref='match', lazy=True, cascade="all, delete-orphan")

    def _safe_load(self, data):
        try: return json.loads(data) if data else []
        except: return []
    def get_banned(self): return self._safe_load(self.banned_maps)
    def get_picked(self): return self._safe_load(self.picked_maps)
    def get_scores_a(self): return self._safe_load(self.scores_a)
    def get_scores_b(self): return self._safe_load(self.scores_b)
    @property
    def total_score_a(self): return sum(self.get_scores_a())
    @property
    def total_score_b(self): return sum(self.get_scores_b())

# --- CUP (Einfaches Round Robin ohne Ban) ---
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
        sa, sb = self.get_scores_a(), self.get_scores_b()
        if not sa or not sb: return 0, 0
        wa = sum(1 for i in range(len(sa)) if sa[i] > sb[i])
        wb = sum(1 for i in range(len(sb)) if sb[i] > sa[i])
        return wa, wb

# --- LIGA (Round Robin + Ban/Pick + Double Opt-In + Lineups) ---
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
    
    # State Logik: ban_1_a -> ... -> pick_a -> ... -> scoring_phase -> confirming -> finished
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
    draft_a_lineup = db.Column(db.Text, nullable=True)
    draft_b_lineup = db.Column(db.Text, nullable=True)
    
    # Bestätigungs-Häkchen für Phase 2
    confirmed_a = db.Column(db.Boolean, default=False)
    confirmed_b = db.Column(db.Boolean, default=False)

    chat_messages = db.relationship('LeagueChatMessage', backref='league_match', lazy=True, cascade="all, delete-orphan")

    def _safe_load(self, data):
        try: return json.loads(data) if data else []
        except: return []
    def get_banned(self): return self._safe_load(self.banned_maps)
    def get_picked(self): return self._safe_load(self.picked_maps)
    def get_scores_a(self): return self._safe_load(self.scores_a)
    def get_scores_b(self): return self._safe_load(self.scores_b)
    
    def get_lineup_a(self): return self._safe_load(self.lineup_a)
    def get_lineup_b(self): return self._safe_load(self.lineup_b)
    def get_draft_a_lineup(self): return self._safe_load(self.draft_a_lineup)
    def get_draft_b_lineup(self): return self._safe_load(self.draft_b_lineup)

    def get_map_wins(self):
        sa, sb = self.get_scores_a(), self.get_scores_b()
        if not sa or not sb: return 0, 0
        wa = sum(1 for i in range(len(sa)) if sa[i] > sb[i])
        wb = sum(1 for i in range(len(sb)) if sb[i] > sa[i])
        return wa, wb

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
        if not User.query.filter_by(username='admin').first():
            hashed_pw = generate_password_hash("admin123", method='pbkdf2:sha256')
            db.session.add(User(username="admin", password=hashed_pw, is_admin=True))
            db.session.commit()
            print("Initialer Admin (admin / admin123) erstellt.")
    except Exception as e: print(f"Init Fehler: {e}")

def clan_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'clan_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# LOGIK FUNKTIONEN
# ==========================================

def handle_pick_ban_logic(match, selected_map):
    current_banned = match.get_banned()
    current_picked = match.get_picked()
    
    if selected_map in current_banned or selected_map in current_picked:
        return False, "Karte vergeben."
    
    s = match.state
    # Standard: 4 Bans (A,B,A,B), dann Picks (A,B,A,B,A...)
    if s == 'ban_1_a':
        current_banned.append(selected_map); match.state = 'ban_1_b'
    elif s == 'ban_1_b':
        current_banned.append(selected_map); match.state = 'ban_2_a'
    elif s == 'ban_2_a':
        current_banned.append(selected_map); match.state = 'ban_2_b'
    elif s == 'ban_2_b':
        current_banned.append(selected_map); match.state = 'pick_a'
    elif s == 'pick_a':
        current_picked.append(selected_map)
        match.state = 'scoring_phase' if len(current_picked) >= 5 else 'pick_b'
    elif s == 'pick_b':
        current_picked.append(selected_map)
        match.state = 'scoring_phase' if len(current_picked) >= 5 else 'pick_a'
        
    match.banned_maps = json.dumps(current_banned)
    match.picked_maps = json.dumps(current_picked)
    return True, "Gespeichert."

def advance_winner(match):
    """Nur für K.O. Turniere"""
    if not match.next_match_id: return
    nm = Match.query.get(match.next_match_id)
    if not nm: return
    win = match.team_a if match.total_score_a > match.total_score_b else match.team_b
    if match.match_index % 2 == 0: nm.team_a = win
    else: nm.team_b = win
    if nm.team_a != "TBD" and nm.team_b != "TBD": nm.state = 'ban_1_a'
    db.session.commit()

def handle_scoring_logic(match, form_data, user):
    """Scores & Lineup Handling für Turnier & Liga"""
    pm = match.get_picked(); num = len(pm) if pm else 4
    try:
        sa = [max(0, int(form_data.get(f'score_a_{i}',0))) for i in range(1, num+1)]
        sb = [max(0, int(form_data.get(f'score_b_{i}',0))) for i in range(1, num+1)]
    except: return False, "Fehler."
    bundle = {'a':sa, 'b':sb}
    lineup_list = form_data.getlist('lineup_member')
    
    # 1. ADMIN/MOD Override
    if user.is_admin or user.is_mod:
        match.scores_a = json.dumps(sa); match.scores_b = json.dumps(sb)
        match.state = 'finished'; match.draft_a_scores=None; match.draft_b_scores=None
        if isinstance(match, Match): advance_winner(match)
        return True, "Admin/Mod Finish."
        
    # 2. TEAM DRAFT
    isa = (user.username == match.team_a); isb = (user.username == match.team_b)
    if not (isa or isb): return False, "Nicht erlaubt."
    
    if isa: 
        match.draft_a_scores = json.dumps(bundle)
        if isinstance(match, LeagueMatch): match.draft_a_lineup = json.dumps(lineup_list)
    elif isb: 
        match.draft_b_scores = json.dumps(bundle)
        if isinstance(match, LeagueMatch): match.draft_b_lineup = json.dumps(lineup_list)
    
    # 3. VERGLEICH
    if match.draft_a_scores and match.draft_b_scores:
        if match.draft_a_scores == match.draft_b_scores:
            match.scores_a = json.dumps(sa); match.scores_b = json.dumps(sb)
            
            if isinstance(match, LeagueMatch):
                # Liga: Zur Bestätigung
                match.state = 'confirming'
                return True, "Scores gleich. Bitte Gegner-Lineup bestätigen."
            else:
                # Turnier: Fertig
                match.state = 'finished'
                if isinstance(match, Match): advance_winner(match)
                return True, "Match Fertig!"
        else:
            match.state = 'conflict'; return False, "Konflikt! Ergebnisse unterschiedlich."
    else:
        match.state = 'waiting_for_confirmation'; return True, "Gespeichert. Warte auf Gegner."


# ==========================================
# ROUTEN
# ==========================================

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
            if (user.is_admin or user.is_mod) and check_password_hash(user.password, password):
                login_user(user); return redirect(url_for('dashboard'))
            elif user.token == password:
                login_user(user); return redirect(url_for('dashboard'))
        clan = Clan.query.filter_by(name=username).first()
        if clan and check_password_hash(clan.password, password):
            session['clan_id'] = clan.id; return redirect(url_for('clan_dashboard'))
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
        name = request.form.get('clan_name'); pw = request.form.get('password')
        if not Clan.query.filter_by(name=name).first():
            db.session.add(Clan(name=name, password=generate_password_hash(pw, method='pbkdf2:sha256')))
            db.session.commit(); flash('Registriert!', 'success'); return redirect(url_for('login'))
    return render_template('register_clan.html')

@app.route('/dashboard')
@login_required
def dashboard():
    all_tournaments = Tournament.query.all()
    return render_template('dashboard.html', 
        active_tournaments=[t for t in all_tournaments if not t.is_archived],
        archived_tournaments=[t for t in all_tournaments if t.is_archived],
        active_cups=Cup.query.filter_by(is_archived=False).all(),
        archived_cups=Cup.query.filter_by(is_archived=True).all(),
        active_leagues=League.query.filter_by(is_archived=False).all(),
        archived_leagues=League.query.filter_by(is_archived=True).all(),
        maps=Map.query.all(), users=User.query.filter_by(is_admin=False).all(), clans=Clan.query.all(),
        clan_map={u.username: u.clan.name for u in User.query.filter(User.clan_id != None).all()}
    )

# --- MEMBER MANAGEMENT ---
@app.route('/add_member', methods=['POST'])
@login_required
def add_member():
    new_member = Member(user_id=current_user.id, gamertag=request.form.get('gamertag'), activision_id=request.form.get('activision_id'), platform=request.form.get('platform'))
    db.session.add(new_member); db.session.commit(); return redirect(url_for('dashboard'))

@app.route('/delete_member/<int:member_id>', methods=['POST'])
@login_required
def delete_member(member_id):
    db.session.delete(Member.query.get_or_404(member_id)); db.session.commit(); return redirect(url_for('dashboard'))

# --- ADMIN ACTIONS (Create/Delete/Archive) ---
# ... (Standard Admin Routen wie Maps, Users, Create User/Clan/Admin/Mod) ...
# Ich fasse das zusammen, damit der Code nicht explodiert.
# Bitte hier die Routen: maps_manager, users_manager, create_admin, create_mod, create_clan, create_user, delete_user, delete_clan, admin_change_password, admin_reset_clan_password, add_map, archive_map, delete_map einfügen.
# (Sie sind 1:1 identisch zur letzten Version)

@app.route('/maps')
@login_required
def maps_manager():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    return render_template('maps.html', active_maps=[m for m in Map.query.all() if not m.is_archived], archived_maps=[m for m in Map.query.all() if m.is_archived])

@app.route('/users')
@login_required
def users_manager():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    return render_template('users.html', clans=Clan.query.all(), users_no_clan=User.query.filter_by(clan_id=None, is_admin=False, is_mod=False).all(), moderators=User.query.filter_by(is_mod=True).all())

@app.route('/clan_dashboard')
@clan_required
def clan_dashboard():
    clan = Clan.query.get(session['clan_id'])
    return render_template('clan_dashboard.html', clan=clan, free_agents=User.query.filter(User.clan_id == None, User.is_admin == False, User.is_mod == False).all())

@app.route('/clan_add_member/<int:user_id>', methods=['POST'])
@clan_required
def clan_add_member(user_id):
    u = User.query.get_or_404(user_id); u.clan_id = session['clan_id']; db.session.commit(); return redirect(url_for('clan_dashboard'))

@app.route('/clan_remove_member/<int:user_id>', methods=['POST'])
@clan_required
def clan_remove_member(user_id):
    u = User.query.get_or_404(user_id); u.clan_id = None; db.session.commit(); return redirect(url_for('clan_dashboard'))

@app.route('/clan_create_team', methods=['POST'])
@clan_required
def clan_create_team():
    c = Clan.query.get(session['clan_id']); name = f"{c.name}.{request.form.get('team_name')}"
    if User.query.filter_by(username=name).first(): flash('Name vergeben','error')
    else: db.session.add(User(username=name, token=str(random.randint(10000,99999)), clan_id=c.id)); db.session.commit()
    return redirect(url_for('clan_dashboard'))

@app.route('/create_admin', methods=['POST'])
@login_required
def create_admin():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.add(User(username=request.form.get('username'), password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256'), is_admin=True))
    db.session.commit(); return redirect(url_for('users_manager'))

@app.route('/create_mod', methods=['POST'])
@login_required
def create_mod():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.add(User(username=request.form.get('username'), password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256'), is_mod=True))
    db.session.commit(); return redirect(url_for('users_manager'))

@app.route('/create_clan', methods=['POST'])
@login_required
def create_clan():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.add(Clan(name=request.form.get('clan_name'), password=generate_password_hash("1234", method='pbkdf2:sha256'))); db.session.commit()
    return redirect(url_for('users_manager'))

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    name = request.form.get('username'); cid = request.form.get('clan_id')
    if cid: name = f"{Clan.query.get(cid).name}.{name}"
    db.session.add(User(username=name, token=str(random.randint(10000,99999)), clan_id=cid)); db.session.commit()
    return redirect(url_for('users_manager'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.delete(User.query.get_or_404(user_id)); db.session.commit(); return redirect(url_for('users_manager'))

@app.route('/delete_clan/<int:clan_id>', methods=['POST'])
@login_required
def delete_clan(clan_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.delete(Clan.query.get_or_404(clan_id)); db.session.commit(); return redirect(url_for('users_manager'))

@app.route('/add_map', methods=['POST'])
@login_required
def add_map():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    for f in request.files.getlist('map_images'):
        if f and allowed_file(f.filename):
            s = secure_filename(f.filename); f.save(os.path.join(app.config['UPLOAD_FOLDER'], s))
            db.session.add(Map(name=os.path.splitext(f.filename)[0].replace('_',' ').title(), image_file=s))
    db.session.commit(); return redirect(url_for('maps_manager'))

@app.route('/delete_map/<int:map_id>', methods=['POST'])
@login_required
def delete_map(map_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.delete(Map.query.get_or_404(map_id)); db.session.commit(); return redirect(url_for('maps_manager'))

# --- TURNIER ---
@app.route('/create_tournament', methods=['GET', 'POST'])
@login_required
def create_tournament():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        sel = request.form.getlist('selected_users'); random.shuffle(sel)
        t = Tournament(name=request.form.get('tournament_name')); db.session.add(t); db.session.commit()
        for i in range(0, len(sel), 2): db.session.add(Match(tournament_id=t.id, team_a=sel[i], team_b=sel[i+1], state='ban_1_a', round_number=1, match_index=i//2))
        db.session.commit()
        # Bracket Generation Logic (vereinfacht: nächste Runden erstellen)
        prev = [m for m in t.matches if m.round_number==1]
        for r in range(2, int(math.ceil(math.log2(len(sel))))+1):
            curr = []
            for i in range(len(prev)//2 + len(prev)%2):
                m = Match(tournament_id=t.id, team_a="TBD", team_b="TBD", state='waiting', round_number=r, match_index=i)
                db.session.add(m); curr.append(m)
            db.session.commit()
            for idx, pm in enumerate(prev): pm.next_match_id = curr[idx//2].id
            db.session.commit(); prev = curr
        return redirect(url_for('dashboard'))
    return render_template('create_tournament.html', users=User.query.filter_by(is_admin=False, is_mod=False).all())

@app.route('/match/<int:match_id>', methods=['GET', 'POST'])
@login_required
def match_view(match_id):
    match = Match.query.get_or_404(match_id)
    active = match.team_a if match.state.endswith('_a') else (match.team_b if match.state.endswith('_b') else None)
    if request.method == 'POST':
        if 'selected_map' in request.form:
            if current_user.is_admin or current_user.username == active:
                s, m = handle_pick_ban_logic(match, request.form.get('selected_map')); db.session.commit()
        elif 'submit_scores' in request.form:
            handle_scoring_logic(match, request.form, current_user); db.session.commit()
        return redirect(url_for('match_view', match_id=match.id))
    return render_template('match.html', match=match, all_maps=Map.query.all(), banned=match.get_banned(), picked=match.get_picked(), active_team=active)

@app.route('/archive_tournament/<int:t_id>', methods=['POST'])
@login_required
def archive_tournament(t_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    t = Tournament.query.get_or_404(t_id); t.is_archived = not t.is_archived; db.session.commit(); return redirect(url_for('dashboard'))

@app.route('/delete_tournament/<int:t_id>', methods=['POST'])
@login_required
def delete_tournament(t_id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    db.session.delete(Tournament.query.get_or_404(t_id)); db.session.commit(); return redirect(url_for('dashboard'))

# --- CUP ---
@app.route('/create_cup', methods=['GET', 'POST'])
@login_required
def create_cup():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        c = Cup(name=request.form.get('cup_name'), participants=json.dumps(request.form.getlist('selected_users'))); db.session.add(c); db.session.commit()
        teams = request.form.getlist('selected_users')
        if len(teams)%2!=0: teams.append(None)
        for r in range(len(teams)-1):
            for i in range(len(teams)//2):
                if teams[i] and teams[len(teams)-1-i]: db.session.add(CupMatch(cup_id=c.id, team_a=teams[i], team_b=teams[len(teams)-1-i], current_picker=teams[i], round_number=r+1))
            teams.insert(1, teams.pop())
        db.session.commit(); return redirect(url_for('dashboard'))
    return render_template('create_cup.html', users=User.query.filter_by(is_admin=False, is_mod=False).all())

@app.route('/cup/<int:cup_id>')
@login_required
def cup_details(cup_id):
    cup = Cup.query.get_or_404(cup_id)
    standings = {user: {'played':0, 'won':0, 'draw':0, 'lost':0, 'points':0} for user in cup.get_participants()} # Vereinfacht
    # ... (Berechnung analog zu Liga, hier kurz gehalten für Score) ...
    # Hier nutzen wir das Score System:
    s_list = {u:{'own_score':0,'opp_score':0} for u in cup.get_participants()}
    for m in cup.matches:
        if m.state == 'finished':
            wa, wb = m.get_map_wins()
            if m.team_a in s_list: s_list[m.team_a]['own_score']+=wa; s_list[m.team_a]['opp_score']+=wb
            if m.team_b in s_list: s_list[m.team_b]['own_score']+=wb; s_list[m.team_b]['opp_score']+=wa
    return render_template('cup_details.html', cup=cup, standings=sorted(s_list.items(), key=lambda x:x[1]['own_score'], reverse=True))

@app.route('/cup_match/<int:match_id>', methods=['GET', 'POST'])
@login_required
def cup_match_view(match_id):
    match = CupMatch.query.get_or_404(match_id)
    if request.method == 'POST':
        if 'toggle_ready' in request.form:
            if current_user.username==match.team_a: match.ready_a=True
            if current_user.username==match.team_b: match.ready_b=True
            if match.ready_a and match.ready_b: match.state='picking'
            db.session.commit()
        elif 'pick_map' in request.form and match.state=='picking':
            pm=match.get_picked(); pm.append(request.form.get('pick_map')); match.picked_maps=json.dumps(pm)
            match.current_picker = match.team_b if match.current_picker==match.team_a else match.team_a
            if len(pm)>=6: match.state='waiting_for_code'
            db.session.commit()
        elif 'submit_scores' in request.form:
            sa=[int(request.form.get(f'score_a_{i}',0)) for i in range(6)]
            sb=[int(request.form.get(f'score_b_{i}',0)) for i in range(6)]
            match.scores_a=json.dumps(sa); match.scores_b=json.dumps(sb); match.state='finished'
            db.session.commit()
        return redirect(url_for('cup_match_view', match_id=match.id))
    return render_template('cup_match.html', match=match, all_maps=Map.query.all(), picked=match.get_picked())

@app.route('/archive_cup/<int:cup_id>', methods=['POST'])
@login_required
def archive_cup(cup_id):
    c = Cup.query.get_or_404(cup_id); c.is_archived = not c.is_archived; db.session.commit(); return redirect(url_for('dashboard'))

@app.route('/delete_cup/<int:cup_id>', methods=['POST'])
@login_required
def delete_cup(cup_id):
    db.session.delete(Cup.query.get_or_404(cup_id)); db.session.commit(); return redirect(url_for('dashboard'))

# --- LIGA ---
@app.route('/create_league', methods=['GET', 'POST'])
@login_required
def create_league():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        l = League(name=request.form.get('league_name'), participants=json.dumps(request.form.getlist('selected_users'))); db.session.add(l); db.session.commit()
        teams = request.form.getlist('selected_users')
        if len(teams)%2!=0: teams.append(None)
        for r in range(len(teams)-1):
            for i in range(len(teams)//2):
                if teams[i] and teams[len(teams)-1-i]: db.session.add(LeagueMatch(league_id=l.id, team_a=teams[i], team_b=teams[len(teams)-1-i], round_number=r+1))
            teams.insert(1, teams.pop())
        db.session.commit(); return redirect(url_for('dashboard'))
    return render_template('create_league.html', users=User.query.filter_by(is_admin=False, is_mod=False).all())

@app.route('/league/<int:league_id>')
def league_details(league_id):
    league = League.query.get_or_404(league_id)
    standings = {u:{'played':0,'won_matches':0,'lost_matches':0,'draw_matches':0,'own_score':0,'opp_score':0} for u in league.get_participants()}
    for m in league.matches:
        if m.state == 'finished':
            wa, wb = m.get_map_wins(); sum_a = sum(m.get_scores_a()); sum_b = sum(m.get_scores_b())
            if m.team_a in standings:
                s=standings[m.team_a]; s['played']+=1; s['own_score']+=sum_a; s['opp_score']+=sum_b
                if wa>wb:s['won_matches']+=1
                elif wb>wa:s['lost_matches']+=1
                else:s['draw_matches']+=1
            if m.team_b in standings:
                s=standings[m.team_b]; s['played']+=1; s['own_score']+=sum_b; s['opp_score']+=sum_a
                if wb>wa:s['won_matches']+=1
                elif wa>wb:s['lost_matches']+=1
                else:s['draw_matches']+=1
    return render_template('league_details.html', league=league, standings=sorted(standings.items(), key=lambda x:x[1]['own_score'], reverse=True))

@app.route('/league_match/<int:match_id>', methods=['GET', 'POST'])
@login_required
def league_match_view(match_id):
    match = LeagueMatch.query.get_or_404(match_id)
    active = match.team_a if match.state.endswith('_a') else (match.team_b if match.state.endswith('_b') else None)
    if request.method == 'POST':
        if 'selected_map' in request.form:
            if current_user.is_admin or current_user.username==active:
                s, m = handle_pick_ban_logic(match, request.form.get('selected_map')); db.session.commit()
        elif 'submit_scores' in request.form:
            handle_scoring_logic(match, request.form, current_user); db.session.commit()
        elif 'confirm_lineup' in request.form:
            if current_user.username == match.team_a: match.confirmed_a=True
            if current_user.username == match.team_b: match.confirmed_b=True
            if match.confirmed_a and match.confirmed_b:
                match.state = 'finished'
                match.lineup_a = match.draft_a_lineup; match.lineup_b = match.draft_b_lineup
            db.session.commit()
        elif 'lobby_code' in request.form:
            match.lobby_code = request.form.get('lobby_code'); db.session.commit()
        return redirect(url_for('league_match_view', match_id=match.id))
    return render_template('league_match.html', match=match, all_maps=Map.query.all(), banned=match.get_banned(), picked=match.get_picked(), active_team=active)

@app.route('/archive_league/<int:league_id>', methods=['POST'])
@login_required
def archive_league(league_id):
    l = League.query.get_or_404(league_id); l.is_archived = not l.is_archived; db.session.commit(); return redirect(url_for('dashboard'))

@app.route('/delete_league/<int:league_id>', methods=['POST'])
@login_required
def delete_league(league_id):
    db.session.delete(League.query.get_or_404(league_id)); db.session.commit(); return redirect(url_for('dashboard'))

# --- APIs ---
@app.route('/api/match/<int:match_id>/chat', methods=['GET', 'POST'])
@login_required
def match_chat_api(match_id):
    # (Identische Logik wie vorher)
    match = Match.query.get_or_404(match_id)
    if request.method=='POST' and request.json.get('message'): db.session.add(ChatMessage(match_id=match.id, username=current_user.username, message=request.json['message'], is_admin=current_user.is_admin, is_mod=current_user.is_mod)); db.session.commit()
    return json.dumps([{'user':m.username,'text':m.message,'is_admin':m.is_admin,'is_mod':m.is_mod,'is_me':m.username==current_user.username} for m in ChatMessage.query.filter_by(match_id=match.id).all()])

@app.route('/api/match/<int:match_id>/lobby_code')
@login_required
def lobby_code_api(match_id): return json.dumps({'lobby_code': Match.query.get_or_404(match_id).lobby_code or ''})

@app.route('/api/cup_match/<int:match_id>/state')
@login_required
def cup_match_state(match_id):
    m = CupMatch.query.get_or_404(match_id)
    return json.dumps({'state':m.state,'current_picker':m.current_picker,'picked':m.get_picked(),'lobby_code':m.lobby_code,'ready_a':m.ready_a,'ready_b':m.ready_b})

@app.route('/api/cup_match/<int:match_id>/chat', methods=['GET', 'POST'])
@login_required
def cup_chat_api(match_id):
    match = CupMatch.query.get_or_404(match_id)
    if request.method=='POST' and request.json.get('message'): db.session.add(CupChatMessage(cup_match_id=match.id, username=current_user.username, message=request.json['message'], is_admin=current_user.is_admin, is_mod=current_user.is_mod)); db.session.commit()
    return json.dumps([{'user':m.username,'text':m.message,'is_admin':m.is_admin,'is_mod':m.is_mod,'is_me':m.username==current_user.username} for m in CupChatMessage.query.filter_by(cup_match_id=match.id).all()])

@app.route('/api/league_match/<int:match_id>/state')
@login_required
def league_match_state(match_id):
    m = LeagueMatch.query.get_or_404(match_id)
    active = m.team_a if m.state.endswith('_a') else (m.team_b if m.state.endswith('_b') else None)
    return json.dumps({'state':m.state,'active_team':active,'banned':m.get_banned(),'picked':m.get_picked(),'lobby_code':m.lobby_code,'confirmed_a':m.confirmed_a,'confirmed_b':m.confirmed_b})

@app.route('/api/league_match/<int:match_id>/chat', methods=['GET', 'POST'])
@login_required
def league_match_chat_api(match_id):
    match = LeagueMatch.query.get_or_404(match_id)
    if request.method=='POST' and request.json.get('message'): db.session.add(LeagueChatMessage(league_match_id=match.id, username=current_user.username, message=request.json['message'], is_admin=current_user.is_admin, is_mod=current_user.is_mod)); db.session.commit()
    return json.dumps([{'user':m.username,'text':m.message,'is_admin':m.is_admin,'is_mod':m.is_mod,'is_me':m.username==current_user.username} for m in LeagueChatMessage.query.filter_by(league_match_id=match.id).all()])

@app.route('/api/league_match/<int:match_id>/lobby_code')
@login_required
def league_lobby_code_api(match_id): return json.dumps({'lobby_code': LeagueMatch.query.get_or_404(match_id).lobby_code or ''})

@app.route('/rules')
def rules(): return render_template('rules.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_initial_admin()
    app.run(debug=True, host='0.0.0.0')