import os
import uuid
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, emit, join_room
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
from dotenv import load_dotenv
from flask import abort

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'insecure-default')
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)

# ---------- DB 연결 ----------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                report_count INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                balance INTEGER DEFAULT 10000
            )
        """)
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN role TEXT DEFAULT 'user'")
        except sqlite3.OperationalError:
            pass
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                report_count INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0,
                is_sold INTEGER DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_log (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS private_chat_log (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                room TEXT NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.commit()
 
@app.route('/init-admin-once')
def init_admin_once():
    db = get_db()
    cursor = db.cursor()

    username = 'admin'
    password = 'admin123'

    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    if cursor.fetchone():
        return "이미 admin 계정이 존재합니다."

    from werkzeug.security import generate_password_hash
    admin_id = str(uuid.uuid4())
    hashed_pw = generate_password_hash(password)
    cursor.execute("""
        INSERT INTO user (id, username, password, bio, role, is_active, balance)
        VALUES (?, ?, ?, '', 'admin', 1, 10000)
    """, (admin_id, username, hashed_pw))
    db.commit()
    return "✅ 관리자 계정이 생성되었습니다. ID: admin / PW: admin123"


# ✅ 관리자 페이지 데이터 연동 + 차단 해제/휴먼 해제 처리

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin_user = cursor.fetchone()

    if admin_user['role'] != 'admin':
        abort(403)

    cursor.execute("SELECT * FROM user ORDER BY username ASC")
    all_users = cursor.fetchall()

    cursor.execute("SELECT * FROM product ORDER BY title ASC")
    all_products = cursor.fetchall()

    cursor.execute("SELECT * FROM user WHERE report_count >= 1 ORDER BY report_count DESC")
    reported_users = cursor.fetchall()

    cursor.execute("SELECT * FROM product WHERE report_count >= 1 ORDER BY report_count DESC")
    reported_products = cursor.fetchall()

    return render_template(
        "admin.html",
        all_users=all_users,
        all_products=all_products,
        reported_users=reported_users,
        reported_products=reported_products
    )

# ✅ 사용자 휴면 해제
@app.route('/admin/unblock-user/<user_id>', methods=['POST'])
def admin_unblock_user(user_id):
    if 'user_id' not in session:
        abort(403)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET is_active = 1 WHERE id = ?", (user_id,))
    db.commit()
    flash("사용자 계정이 다시 활성화되었습니다.")
    return redirect(url_for('admin'))

# ✅ 상품 차단 해제
@app.route('/admin/unblock-product/<product_id>', methods=['POST'])
def admin_unblock_product(product_id):
    if 'user_id' not in session:
        abort(403)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE product SET is_blocked = 0 WHERE id = ?", (product_id,))
    db.commit()
    flash("상품 차단이 해제되었습니다.")
    return redirect(url_for('admin'))



@app.route('/admin/block-user/<user_id>', methods=['POST'])
def admin_block_user(user_id):
    if 'user_id' not in session:
        abort(403)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET is_active = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash("사용자를 휴면 상태로 전환했습니다.")
    return redirect(url_for('admin'))

@app.route('/admin/block-product/<product_id>', methods=['POST'])
def admin_block_product(product_id):
    if 'user_id' not in session:
        abort(403)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 차단되었습니다.")
    return redirect(url_for('admin'))

@app.route('/admin/delete-product/<product_id>', methods=['POST'])
def admin_delete_product(product_id):
    if 'user_id' not in session:
        abort(403)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('admin'))
       
        
@app.route('/buy/<product_id>', methods=['POST'])
def buy_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product or product['is_sold'] or product['is_blocked']:
        flash("구매할 수 없는 상품입니다.")
        return redirect(url_for('dashboard'))

    price = int(product['price'])

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    buyer = cursor.fetchone()
    if buyer['balance'] < price:
        flash("잔액이 부족합니다.")
        return redirect(url_for('view_product', product_id=product_id))

    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    # 거래 처리
    cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (buyer['balance'] - price, buyer['id']))
    cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (seller['balance'] + price, seller['id']))
    cursor.execute("UPDATE product SET is_sold = 1 WHERE id = ?", (product_id,))
    db.commit()

    flash("구매가 완료되었습니다!")
    return redirect(url_for('dashboard'))

@app.route('/my-purchases')
def my_purchases():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT p.title, p.price, u.username AS seller_name
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.is_sold = 1 AND p.id IN (
            SELECT id FROM product
            WHERE is_sold = 1 AND id NOT IN (
                SELECT id FROM product WHERE seller_id = ?
            )
        )
    """, (session['user_id'],))
    purchases = cursor.fetchall()
    return render_template('my_purchases.html', purchases=purchases)

@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = request.args.get('q', '').strip()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if query:
        cursor.execute("""
            SELECT * FROM product
            WHERE is_blocked = 0 AND is_sold = 0 AND title LIKE ?
        """, (f"%{query}%",))
    else:
        cursor.execute("SELECT * FROM product WHERE is_blocked = 0 AND is_sold = 0")

    products = cursor.fetchall()
    return render_template('dashboard.html', user=user, products=products, query=query)

@app.route('/my-sales')
def my_sales():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT title, price
        FROM product
        WHERE seller_id = ? AND is_sold = 1
    """, (session['user_id'],))
    sales = cursor.fetchall()
    return render_template('my_sales.html', sales=sales)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        hashed_pw = generate_password_hash(password)
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_pw))
        db.commit()
        flash('회원가입 완료. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user is None:
            flash("존재하지 않는 사용자입니다.")
            return redirect(url_for('login'))

        if user['is_active'] == 0:
            flash("해당 계정은 휴면 상태입니다.")
            return redirect(url_for('login'))

        if check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash('로그인 성공!')

            if user['role'] == 'admin':
                return redirect(url_for('admin'))

            return redirect(url_for('dashboard'))
        else:
            flash('비밀번호가 틀렸습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')

# 나머지 라우트는 수정 없이 유지됨
@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    cursor.execute("SELECT * FROM product WHERE is_blocked = 0 AND is_sold = 0")
    products = cursor.fetchall()
    cursor.execute("""
        SELECT c.message, c.timestamp, u.username
        FROM chat_log c
        JOIN user u ON c.sender_id = u.id
        ORDER BY c.timestamp ASC
    """)
    chat_logs = cursor.fetchall()
    return render_template('dashboard.html', user=user, products=products, chat_logs=chat_logs)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = escape(request.form.get('bio', ''))
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    return render_template('profile.html', user=user)

@app.route('/edit-password', methods=['GET', 'POST'])
def edit_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if not check_password_hash(user['password'], current):
            flash('현재 비밀번호가 일치하지 않습니다.')
        elif new != confirm:
            flash('새 비밀번호가 일치하지 않습니다.')
        else:
            hashed = generate_password_hash(new)
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed, session['user_id']))
            db.commit()
            flash('비밀번호가 변경되었습니다.')
            return redirect(url_for('profile'))
    return render_template('edit_password.html')

@app.route('/my-products')
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    my_products = cursor.fetchall()
    return render_template('my_products.html', my_products=my_products)

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = escape(request.form['title'])
        desc = escape(request.form['description'])
        price = escape(request.form['price'])
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
                       (product_id, title, desc, price, session['user_id']))
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['is_blocked']:
        flash("해당 상품은 차단되어 볼 수 없습니다.")
        return redirect(url_for('dashboard'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

@app.route('/user/<user_id>')
def user_detail(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    return render_template('user_detail.html', user=user)

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        target_id = escape(request.form['target_id'])
        reason = escape(request.form['reason'])
        report_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
                       (report_id, session['user_id'], target_id, reason))

        cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
        target_user = cursor.fetchone()
        if target_user:
            new_count = target_user['report_count'] + 1
            is_active = 0 if new_count >= 3 else 1
            cursor.execute("UPDATE user SET report_count = ?, is_active = ? WHERE id = ?",
                           (new_count, is_active, target_id))

        cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
        target_product = cursor.fetchone()
        if target_product:
            new_count = target_product['report_count'] + 1
            is_blocked = 1 if new_count >= 3 else 0
            cursor.execute("UPDATE product SET report_count = ?, is_blocked = ? WHERE id = ?",
                           (new_count, is_blocked, target_id))

        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')


@app.route('/chat/<target_id>')
def chat_private(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if target_id == session['user_id']:
        flash("자기 자신과는 채팅할 수 없습니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
    target_user = cursor.fetchone()
    if not target_user:
        flash("채팅 대상 유저를 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))
    
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    room_id = f"room_{'_'.join(sorted([target_id, session['user_id']]))}"

    cursor.execute("""
        SELECT p.message, p.timestamp, u.username
        FROM private_chat_log p
        JOIN user u ON p.sender_id = u.id
        WHERE p.room = ?
        ORDER BY p.timestamp ASC
    """, (room_id,))
    logs = cursor.fetchall()

    return render_template(
        'chat_private.html',
        target_user=target_user,
        current_user=current_user,
        room_id=room_id,
        logs=logs
    )


@app.route('/users')
def user_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, bio FROM user WHERE id != ?", (session['user_id'],))
    users = cursor.fetchall()
    return render_template('user_list.html', users=users)


# ---------- 채팅 ----------

@socketio.on('send_message')
def handle_send_message(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO chat_log (id, sender_id, message) VALUES (?, ?, ?)",
        (data['message_id'], session['user_id'], data['message'])
    )
    db.commit()

@socketio.on('join_private')
def join_private(data):
    join_room(data['room'])

@socketio.on('send_private_message')
def send_private(data):
    emit('private_message', data, to=data['room'])

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO private_chat_log (id, sender_id, receiver_id, message, room) VALUES (?, ?, ?, ?, ?)",
        (
            str(uuid.uuid4()),
            session['user_id'],
            data['receiver_id'], 
            data['message'],
            data['room']
        )
    )
    db.commit()

if __name__ == '__main__':
    init_db()
    with app.app_context():
        init_admin_once()
    socketio.run(app, debug=True)
