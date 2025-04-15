import os
import uuid
import secrets
import sqlite3
import bcrypt
import html
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send

# === CSRF ===
from flask_wtf.csrf import CSRFProtect

##############################################################################
# 전역 설정
##############################################################################
app = Flask(__name__)

# 실행할 때마다 무작위 SECRET_KEY (시큐어코딩: 하드코딩된 키 지양)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# 세션 만료 (로그인 후 30분)
app.permanent_session_lifetime = timedelta(minutes=30)

# === CSRF ===
# CSRFProtect 활성화
csrf = CSRFProtect(app)

DATABASE = 'market.db'
socketio = SocketIO(app)

SESSION_USER_ID = 'user_id'

##############################################################################
# DB 연결 & 종료
##############################################################################
def get_db():
    """요청마다 SQLite DB 연결을 반환. g._database 캐싱."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """요청 종료 시 DB를 닫음."""
    db = getattr(g, '_database', None)
    if db:
        db.close()

##############################################################################
# DB 초기화 (테이블 생성)
##############################################################################
def init_db():
    with app.app_context():
        db = get_db()
        cur = db.cursor()

        # user 테이블
        cur.execute("""
        CREATE TABLE IF NOT EXISTS user (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT,
            is_admin INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            balance INTEGER DEFAULT 0
        )
        """)

        # product 테이블
        cur.execute("""
        CREATE TABLE IF NOT EXISTS product (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price INTEGER NOT NULL,
            seller_id TEXT NOT NULL,
            is_sold INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0
        )
        """)

        # report 테이블
        cur.execute("""
        CREATE TABLE IF NOT EXISTS report (
            id TEXT PRIMARY KEY,
            reporter_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            reason TEXT NOT NULL
        )
        """)

        # transactions (송금 & 구매내역)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            amount INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        db.commit()

##############################################################################
# 인증/인가 유틸
##############################################################################
def is_logged_in():
    return SESSION_USER_ID in session

def get_current_user():
    if not is_logged_in():
        return None
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM user WHERE id=?", (session[SESSION_USER_ID],))
    return cur.fetchone()

def login_required(func):
    """로그인 안 된 상태의 접근을 막음."""
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        # 정지된 계정 체크
        user = get_current_user()
        if user and user['is_active'] == 0:
            flash('정지된 계정입니다. 관리자에게 문의하세요.')
            session.pop(SESSION_USER_ID, None)
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def admin_required(func):
    """관리자(is_admin=1)만 접근 가능."""
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or user['is_admin'] == 0:
            abort(403)
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

##############################################################################
# 라우트
##############################################################################

@app.route('/')
def index():
    """로그인되어 있으면 대시보드, 아니면 인덱스 페이지."""
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

##############################################################################
# 회원가입 (비밀번호 bcrypt)
##############################################################################
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()

        # 비밀번호 최소 길이 간단 체크
        if len(username) < 3 or len(password) < 4:
            flash('사용자명 혹은 비밀번호가 너무 짧습니다.')
            return redirect(url_for('register'))

        db = get_db()
        cur = db.cursor()
        # 중복 사용자명 체크
        cur.execute("SELECT * FROM user WHERE username=?", (username,))
        if cur.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        # bcrypt 해시
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashed_pw = hashed.decode('utf-8')

        user_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO user (id, username, password) 
            VALUES (?, ?, ?)
        """,(user_id, username, hashed_pw))
        db.commit()
        flash('회원가입 완료! 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

##############################################################################
# 로그인 (bcrypt 체크)
##############################################################################
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM user WHERE username=?", (username,))
        user = cur.fetchone()
        if user:
            stored_hash = user['password'].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                if user['is_active'] == 0:
                    flash('정지된 계정입니다.')
                    return redirect(url_for('login'))
                session[SESSION_USER_ID] = user['id']
                session.permanent = True
                flash('로그인 성공!')
                return redirect(url_for('dashboard'))
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))
    return render_template('login.html')

##############################################################################
# 로그아웃
##############################################################################
@app.route('/logout', methods=['POST','GET'])
def logout():
    # CSRF로 보호하려면 로그아웃도 POST 방식을 선호하지만, 여기서는 GET도 허용
    session.pop(SESSION_USER_ID, None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

##############################################################################
# 대시보드
##############################################################################
@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    user = get_current_user()
    db = get_db()
    cur = db.cursor()

    # 검색어
    q = request.args.get('q','').strip()
    if q:
        like_q = f"%{q}%"
        cur.execute("""
            SELECT * 
            FROM product
            WHERE hidden=0 AND is_sold=0
              AND (title LIKE ? OR description LIKE ?)
            ORDER BY rowid DESC
        """,(like_q, like_q))
    else:
        cur.execute("""
            SELECT * 
            FROM product
            WHERE hidden=0 AND is_sold=0
            ORDER BY rowid DESC
        """)
    products = cur.fetchall()

    return render_template('dashboard.html', user=user, products=products, search_query=q)

##############################################################################
# 프로필
##############################################################################
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    db = get_db()
    cur = db.cursor()
    user = get_current_user()

    if request.method == 'POST':
        bio = request.form.get('bio','')
        # XSS 방지
        bio_escaped = html.escape(bio)
        cur.execute("UPDATE user SET bio=? WHERE id=?", (bio_escaped, user['id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

##############################################################################
# 상품 등록
##############################################################################
@app.route('/product/new', methods=['GET','POST'])
@login_required
def new_product():
    user = get_current_user()
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        desc = request.form.get('description','').strip()
        price_str = request.form.get('price','0').strip()
        db = get_db()
        cur = db.cursor()

        try:
            price = int(price_str)
        except ValueError:
            flash('가격이 숫자가 아닙니다.')
            return redirect(url_for('new_product'))

        if price <= 0:
            flash('가격은 1이상이어야 합니다.')
            return redirect(url_for('new_product'))

        # XSS 방지
        title_escaped = html.escape(title)
        desc_escaped = html.escape(desc)

        pid = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO product (id, title, description, price, seller_id)
            VALUES (?, ?, ?, ?, ?)
        """,(pid, title_escaped, desc_escaped, price, user['id']))
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html', user=user)

##############################################################################
# 상품 상세
##############################################################################
@app.route('/product/<product_id>', methods=['GET'])
@login_required
def view_product(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM product WHERE id=?", (product_id,))
    product = cur.fetchone()
    if not product:
        flash('상품이 존재하지 않습니다.')
        return redirect(url_for('dashboard'))
    if product['hidden'] == 1:
        flash('숨겨진 상품입니다.')
        return redirect(url_for('dashboard'))

    cur.execute("SELECT * FROM user WHERE id=?", (product['seller_id'],))
    seller = cur.fetchone()
    user = get_current_user()
    return render_template('view_product.html', user=user, product=product, seller=seller)

##############################################################################
# 구매하기
##############################################################################
@app.route('/purchase/<product_id>', methods=['POST'])
@login_required
def purchase_product(product_id):
    db = get_db()
    cur = db.cursor()
    user = get_current_user()

    # 상품 조회
    cur.execute("SELECT * FROM product WHERE id=?", (product_id,))
    product = cur.fetchone()
    if not product:
        flash('상품이 존재하지 않습니다.')
        return redirect(url_for('dashboard'))
    if product['is_sold'] == 1:
        flash('이미 판매완료된 상품입니다.')
        return redirect(url_for('dashboard'))

    if user['id'] == product['seller_id']:
        flash('자신이 등록한 상품은 구매할 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 구매자 잔액 확인
    if user['balance'] < product['price']:
        flash('포인트가 부족합니다.')
        return redirect(url_for('dashboard'))

    # 판매자 조회
    cur.execute("SELECT * FROM user WHERE id=?", (product['seller_id'],))
    seller = cur.fetchone()
    new_buyer_bal = user['balance'] - product['price']
    new_seller_bal = seller['balance'] + product['price']

    # 갱신
    cur.execute("UPDATE user SET balance=? WHERE id=?", (new_buyer_bal, user['id']))
    cur.execute("UPDATE user SET balance=? WHERE id=?", (new_seller_bal, seller['id']))
    cur.execute("UPDATE product SET is_sold=1 WHERE id=?", (product_id,))
    # 거래내역
    t_id = str(uuid.uuid4())
    cur.execute("""
        INSERT INTO transactions (id, sender_id, receiver_id, amount)
        VALUES (?, ?, ?, ?)
    """,(t_id, user['id'], seller['id'], product['price']))
    db.commit()

    flash(f"{product['title']} 상품 구매 완료!")
    return redirect(url_for('dashboard'))

##############################################################################
# 신고하기
##############################################################################
@app.route('/report', methods=['GET','POST'])
@login_required
def report():
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    if request.method == 'POST':
        target_id = request.form.get('target_id','').strip()
        reason = request.form.get('reason','').strip()
        reason_escaped = html.escape(reason)
        if not target_id or not reason_escaped:
            flash('신고 대상/사유 누락')
            return redirect(url_for('report'))

        rid = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO report (id, reporter_id, target_id, reason)
            VALUES (?, ?, ?, ?)
        """,(rid, user['id'], target_id, reason_escaped))
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html', user=user)

##############################################################################
# 포인트 송금
##############################################################################
@app.route('/transfer', methods=['GET','POST'])
@login_required
def transfer():
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    if request.method == 'POST':
        receiver_name = request.form.get('receiver','').strip()
        amount_str = request.form.get('amount','0').strip()
        try:
            amount = int(amount_str)
        except ValueError:
            flash('송금액이 올바르지 않습니다.')
            return redirect(url_for('transfer'))
        if amount <= 0:
            flash('송금액은 1 이상이어야 합니다.')
            return redirect(url_for('transfer'))

        # 수신인
        cur.execute("SELECT * FROM user WHERE username=?", (receiver_name,))
        receiver = cur.fetchone()
        if not receiver:
            flash('수신인을 찾을 수 없습니다.')
            return redirect(url_for('transfer'))
        if receiver['id'] == user['id']:
            flash('자기 자신에게 송금 불가')
            return redirect(url_for('transfer'))

        if user['balance'] < amount:
            flash('포인트 부족.')
            return redirect(url_for('transfer'))

        new_sender_bal = user['balance'] - amount
        new_receiver_bal = receiver['balance'] + amount
        cur.execute("UPDATE user SET balance=? WHERE id=?", (new_sender_bal, user['id']))
        cur.execute("UPDATE user SET balance=? WHERE id=?", (new_receiver_bal, receiver['id']))

        t_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO transactions (id, sender_id, receiver_id, amount)
            VALUES (?, ?, ?, ?)
        """,(t_id, user['id'], receiver['id'], amount))
        db.commit()

        flash('송금 완료!')
        return redirect(url_for('dashboard'))
    return render_template('transfer.html', user=user)

##############################################################################
# 관리자(Admin) 페이지
##############################################################################
@app.route('/admin')
@admin_required
def admin_index():
    return render_template('admin_index.html')

@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM user ORDER BY rowid DESC")
    rows = cur.fetchall()
    return render_template('admin_users.html', all_users=rows)

@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM product ORDER BY rowid DESC")
    rows = cur.fetchall()
    return render_template('admin_products.html', all_products=rows)

@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT r.*, u.username as reporter_name
        FROM report r
        JOIN user u ON r.reporter_id=u.id
        ORDER BY r.rowid DESC
    """)
    rows = cur.fetchall()
    return render_template('admin_reports.html', all_reports=rows)

# 관리자: 사용자 차단/해제
@app.route('/admin/user/<user_id>/toggle_active', methods=['POST'])
@admin_required
def admin_toggle_user_active(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM user WHERE id=?", (user_id,))
    target = cur.fetchone()
    if not target:
        flash('해당 사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_users'))
    new_state = 0 if target['is_active'] == 1 else 1
    cur.execute("UPDATE user SET is_active=? WHERE id=?", (new_state, user_id))
    db.commit()
    flash('사용자 활성/정지 변경 완료.')
    return redirect(url_for('admin_users'))

# 관리자: 상품 숨기기/보이기
@app.route('/admin/product/<product_id>/toggle_hidden', methods=['POST'])
@admin_required
def admin_toggle_product_hidden(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM product WHERE id=?", (product_id,))
    item = cur.fetchone()
    if not item:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('admin_products'))
    new_state = 0 if item['hidden'] == 1 else 1
    cur.execute("UPDATE product SET hidden=? WHERE id=?", (new_state, product_id))
    db.commit()
    flash('상품 숨김/노출이 변경되었습니다.')
    return redirect(url_for('admin_products'))

# 관리자: 상품 삭제
@app.route('/admin/product/<product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM product WHERE id=?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_products'))

##############################################################################
# 실시간 채팅 (Socket.IO)
##############################################################################
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    # 길이 제한 / XSS 방지
    msg = data.get('message','')
    if len(msg) > 300:
        msg = msg[:300] + '...'
    safe_msg = html.escape(msg)
    data['message'] = safe_msg
    send(data, broadcast=True)

##############################################################################
# 메인
##############################################################################
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        print("market.db가 없으므로 새로 생성합니다.")
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
