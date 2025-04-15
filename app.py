import os
import uuid
import secrets
import sqlite3
import bcrypt
import html
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send

##############################################################################
# 전역 설정
##############################################################################
app = Flask(__name__)

# 실행할 때마다 무작위 SECRET_KEY를 생성 (32바이트 -> 64자리 hex)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# 세션 만료 (로그인 후 30분 동안 활동 없으면 자동 로그아웃)
app.permanent_session_lifetime = timedelta(minutes=30)

DATABASE = 'market.db'
socketio = SocketIO(app)

# 로그인/관리자 접근용 상수
SESSION_KEY_USER_ID = 'user_id'
SESSION_KEY_IS_ADMIN = 'is_admin'

##############################################################################
# DB 연결 및 종료
##############################################################################
def get_db():
    """
    요청마다 SQLite DB 연결을 반환. g._database에 캐싱하여 재사용.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dictionary처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    """
    요청 종료 시 DB 커넥션 닫기
    """
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

##############################################################################
# DB 초기화 (테이블 생성)
##############################################################################
def init_db():
    with app.app_context():
        db = get_db()
        cur = db.cursor()

        # user 테이블: 사용자 정보 (id, username, password, bio, is_admin, is_active, balance)
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

        # product 테이블: 상품 정보 (id, title, description, price, seller_id)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS product (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price TEXT NOT NULL,
            seller_id TEXT NOT NULL
        )
        """)

        # report 테이블: 신고 정보 (id, reporter_id, target_id, reason)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS report (
            id TEXT PRIMARY KEY,
            reporter_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            reason TEXT NOT NULL
        )
        """)

        # transaction 테이블: 포인트 송금 내역
        cur.execute("""
        CREATE TABLE IF NOT EXISTS transaction (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            amount INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        db.commit()

##############################################################################
# 인증 및 권한 확인 유틸 함수
##############################################################################
def is_logged_in():
    return SESSION_KEY_USER_ID in session

def get_current_user():
    """
    세션에 저장된 user_id로 DB에서 사용자 정보 조회
    """
    if not is_logged_in():
        return None
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM user WHERE id = ?", (session[SESSION_KEY_USER_ID],))
    return cur.fetchone()

def is_admin_user():
    """
    현재 세션 사용자가 관리자(is_admin=1)인지 여부
    """
    user = get_current_user()
    if user and user['is_admin'] == 1:
        return True
    return False

def login_required(func):
    """
    Flask 라우트용 데코레이터: 로그인이 필요.
    """
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def admin_required(func):
    """
    Flask 라우트용 데코레이터: 관리자 계정 필요.
    """
    def wrapper(*args, **kwargs):
        if not is_admin_user():
            abort(403)  # 관리자 아니면 403 Forbidden
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

##############################################################################
# 라우트 구현
##############################################################################

@app.route('/')
def index():
    """
    비로그인 사용자는 /index 보여주고, 로그인 상태면 /dashboard로
    """
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

##############################################################################
# 회원가입 (비밀번호 해시 저장)
##############################################################################
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()

        # 비밀번호 최소 길이, 복잡성 등 간단 검증 예시
        if len(username) < 3 or len(password) < 4:
            flash('유효하지 않은 사용자명/비밀번호입니다.')
            return redirect(url_for('register'))

        # DB에서 username 중복체크
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM user WHERE username = ?", (username,))
        existing = cur.fetchone()
        if existing:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        # bcrypt 해시 생성
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashed_pw = hashed_pw.decode('utf-8')  # DB 저장용 문자열

        user_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO user (id, username, password) VALUES (?, ?, ?)
        """, (user_id, username, hashed_pw))
        db.commit()

        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))

    # GET 메서드 -> 회원가입 폼
    return render_template('register.html')

##############################################################################
# 로그인
##############################################################################
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cur.fetchone()
        if user:
            stored_hash = user['password'].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                # is_active가 0이면 정지된 계정
                if user['is_active'] == 0:
                    flash('정지된 계정입니다. 관리자에게 문의하세요.')
                    return redirect(url_for('login'))

                session[SESSION_KEY_USER_ID] = user['id']
                session.permanent = True
                flash('로그인 성공!')
                return redirect(url_for('dashboard'))
        flash('로그인 실패. 아이디 혹은 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))

    return render_template('login.html')

##############################################################################
# 로그아웃
##############################################################################
@app.route('/logout')
def logout():
    session.pop(SESSION_KEY_USER_ID, None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

##############################################################################
# 대시보드 (상품 목록 + 검색)
##############################################################################
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cur = db.cursor()

    # 현재 사용자
    user = get_current_user()

    # 검색 기능
    q = request.args.get('q','').strip()
    if q:
        # 간단 LIKE 검색 (title, description)
        qparam = f"%{q}%"
        cur.execute("""
            SELECT * FROM product
            WHERE title LIKE ? OR description LIKE ?
            ORDER BY rowid DESC
        """, (qparam,qparam))
    else:
        # 전체 상품 조회
        cur.execute("SELECT * FROM product ORDER BY rowid DESC")

    products = cur.fetchall()
    return render_template('dashboard.html', user=user, products=products, search_query=q)

##############################################################################
# 프로필 (자기소개 등 수정)
##############################################################################
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    db = get_db()
    cur = db.cursor()
    user = get_current_user()

    if request.method == 'POST':
        bio = request.form.get('bio','')
        # 특수문자, 태그 치환으로 XSS 방어
        bio_escaped = html.escape(bio)
        cur.execute("UPDATE user SET bio=? WHERE id=?", (bio_escaped, user['id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    # GET - 현재 프로필 조회
    return render_template('profile.html', user=user)

##############################################################################
# 상품 등록
##############################################################################
@app.route('/product/new', methods=['GET','POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        description = request.form.get('description','').strip()
        price = request.form.get('price','').strip()
        if not title or not description or not price:
            flash('필수값이 누락되었습니다.')
            return redirect(url_for('new_product'))

        # XSS 방지
        title_escaped = html.escape(title)
        desc_escaped = html.escape(description)

        db = get_db()
        cur = db.cursor()
        product_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO product (id, title, description, price, seller_id)
            VALUES (?, ?, ?, ?, ?)
        """,(product_id, title_escaped, desc_escaped, price, session[SESSION_KEY_USER_ID]))
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')

##############################################################################
# 상품 상세 페이지
##############################################################################
@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cur.fetchone()
    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('dashboard'))

    # 판매자 조회
    cur.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cur.fetchone()

    user = get_current_user()
    return render_template('view_product.html', product=product, seller=seller, user=user)

##############################################################################
# 신고하기
##############################################################################
@app.route('/report', methods=['GET','POST'])
@login_required
def report():
    if request.method == 'POST':
        target_id = request.form.get('target_id','').strip()
        reason = request.form.get('reason','').strip()
        if not target_id or not reason:
            flash('신고 대상/사유가 누락되었습니다.')
            return redirect(url_for('report'))

        # XSS 방지
        reason_escaped = html.escape(reason)

        db = get_db()
        cur = db.cursor()
        report_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO report (id, reporter_id, target_id, reason)
            VALUES (?, ?, ?, ?)
        """, (report_id, session[SESSION_KEY_USER_ID], target_id, reason_escaped))
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

##############################################################################
# 관리자용 페이지 - 사용자/상품/신고 관리
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
    cur.execute("SELECT * FROM user")
    all_users = cur.fetchall()
    return render_template('admin_users.html', all_users=all_users)

@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM product ORDER BY rowid DESC")
    all_products = cur.fetchall()
    return render_template('admin_products.html', all_products=all_products)

@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    cur = db.cursor()
    # 신고 + 신고자 username JOIN
    query = """
        SELECT r.*, u.username as reporter_name 
        FROM report r
        JOIN user u ON r.reporter_id = u.id
        ORDER BY r.rowid DESC
    """
    cur.execute(query)
    all_reports = cur.fetchall()
    return render_template('admin_reports.html', all_reports=all_reports)

##############################################################################
# 관리자: 특정 사용자 차단/해제
##############################################################################
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
    new_state = 1 if target['is_active'] == 0 else 0
    cur.execute("UPDATE user SET is_active=? WHERE id=?", (new_state, user_id))
    db.commit()
    flash('사용자 활동 상태가 변경되었습니다.')
    return redirect(url_for('admin_users'))

##############################################################################
# 관리자: 특정 사용자 관리자 권한 on/off
##############################################################################
@app.route('/admin/user/<user_id>/toggle_admin', methods=['POST'])
@admin_required
def admin_toggle_user_admin(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM user WHERE id=?", (user_id,))
    target = cur.fetchone()
    if not target:
        flash('해당 사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_users'))
    new_is_admin = 1 if target['is_admin'] == 0 else 0
    cur.execute("UPDATE user SET is_admin=? WHERE id=?", (new_is_admin, user_id))
    db.commit()
    flash('관리자 권한이 변경되었습니다.')
    return redirect(url_for('admin_users'))

##############################################################################
# 관리자: 상품 삭제
##############################################################################
@app.route('/admin/product/<product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_products'))

##############################################################################
# 사용자 간 포인트 송금
##############################################################################
@app.route('/transfer', methods=['GET','POST'])
@login_required
def transfer():
    db = get_db()
    cur = db.cursor()
    user = get_current_user()

    if request.method == 'POST':
        receiver_username = request.form.get('receiver','').strip()
        amount_str = request.form.get('amount','0').strip()
        try:
            amount = int(amount_str)
        except ValueError:
            flash('송금액이 유효한 숫자가 아닙니다.')
            return redirect(url_for('transfer'))

        if amount <= 0:
            flash('송금액이 0 이하입니다.')
            return redirect(url_for('transfer'))

        # 수신인 조회
        cur.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
        receiver = cur.fetchone()
        if not receiver:
            flash('수신인을 찾을 수 없습니다.')
            return redirect(url_for('transfer'))

        if receiver['id'] == user['id']:
            flash('자기 자신에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))

        # 보낸이 잔액 충분한지 확인
        if user['balance'] < amount:
            flash('포인트 잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        # 트랜잭션
        new_sender_bal = user['balance'] - amount
        new_receiver_bal = receiver['balance'] + amount

        # 두 계정 업데이트
        cur.execute("UPDATE user SET balance=? WHERE id=?", (new_sender_bal, user['id']))
        cur.execute("UPDATE user SET balance=? WHERE id=?", (new_receiver_bal, receiver['id']))

        # 거래내역 기록
        t_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO transaction (id, sender_id, receiver_id, amount)
            VALUES (?, ?, ?, ?)
        """,(t_id, user['id'], receiver['id'], amount))
        db.commit()

        flash('송금이 완료되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('transfer.html', user=user)

##############################################################################
# 실시간 채팅 (Socket.IO)
##############################################################################
@socketio.on('send_message')
def handle_send_message_event(data):
    """
    클라이언트 -> 서버 : 'send_message'
    서버 -> 전체 broadcast
    """
    # 메시지에 추가 정보(고유 message_id, timestamp 등) 부여 가능
    data['message_id'] = str(uuid.uuid4())
    # 간단한 길이 제한 / XSS 방지
    msg = data.get('message','')
    if len(msg) > 300:
        msg = msg[:300] + '...'  # 300자 초과시 자름
    # HTML 특수문자 치환
    msg_escaped = html.escape(msg)
    data['message'] = msg_escaped

    send(data, broadcast=True)

##############################################################################
# 서버 실행
##############################################################################
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        print("초기 DB 생성...")
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
