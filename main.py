# Login, Logout, Forgot password
from flask import Flask, render_template, redirect, url_for, request, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for session management

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "200 per hour"]
)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def sanitize_input(value):
    if value is None:
        return ''
    return re.sub(r"[;'\"]", "", value)

@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('shop'))
        else:
            return render_template("login.html")
    return render_template("login.html")

@app.route("/logged", methods=['GET', 'POST'])
def logged():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template("logged_in.html")

@app.route("/forgot_password", methods=['GET', 'POST'])
def forgor():
    if request.method == "POST":
        username = sanitize_input(request.form.get('username'))
        security_answer = sanitize_input(request.form.get('security_answer'))
        new_password = sanitize_input(request.form.get('new_password'))
        conn = get_db()
        try:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if not user:
                return render_template("forgor.html")
            if security_answer and new_password:
                if security_answer.lower() != user['security_answer'].lower():
                    return render_template("forgor.html", username=username, security_question=user['security_question'])
                conn.execute('UPDATE users SET password = ? WHERE username = ?', (generate_password_hash(new_password), username))
                conn.commit()
                return redirect(url_for('login'))
            return render_template("forgor.html", username=username, security_question=user['security_question'])
        finally:
            conn.close()
    return render_template("forgor.html")

@app.route("/new_account", methods=['GET', 'POST'])
def new_account():
    if request.method == "POST":
        username = sanitize_input(request.form.get('username'))
        password = sanitize_input(request.form.get('password'))
        security_question = sanitize_input(request.form.get('security_question'))
        security_answer = sanitize_input(request.form.get('security_answer'))
        if not all([username, password, security_question, security_answer]):
            return render_template("create.html")
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password, security_question, security_answer) VALUES (?, ?, ?, ?)', (username, generate_password_hash(password), security_question, security_answer.lower()))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template("create.html")
        finally:
            conn.close()
    return render_template("create.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('shop'))

@app.route("/user_dashboard", methods=['GET', 'POST'])
def userdash():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        phone_number = sanitize_input(request.form.get('phone_number'))
        address = sanitize_input(request.form.get('address'))
        if 'profile_icon' in request.files:
            file = request.files['profile_icon']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"{session['user_id']}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                conn = get_db()
                try:
                    conn.execute('UPDATE users SET profile_icon = ? WHERE id = ?', (filename, session['user_id']))
                    conn.commit()
                finally:
                    conn.close()
        conn = get_db()
        try:
            conn.execute('UPDATE users SET phone_number = ?, address = ? WHERE id = ?', (phone_number, address, session['user_id']))
            conn.commit()
        finally:
            conn.close()
    conn = get_db()
    user_info = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template("user_dashboard.html", user_info=user_info)

@app.route("/")
def shop():
    conn = get_db()
    try:
        products_query = """
            SELECT
                p.*,
                (p.quantity - COALESCE(c.reserved, 0)) AS available_quantity
            FROM
                products p
            LEFT JOIN
                (SELECT product_id, COUNT(*) as reserved FROM cart GROUP BY product_id) c
            ON
                p.id = c.product_id
        """
        products = conn.execute(products_query).fetchall()
        return render_template("shop.html", products=products)
    finally:
        conn.close()

@app.route("/product/<int:product_id>")
def product_detail(product_id):
    conn = get_db()
    try:
        product_query = """
            SELECT
                p.*,
                (p.quantity - COALESCE(c.reserved, 0)) AS available_quantity
            FROM
                products p
            LEFT JOIN
                (SELECT product_id, COUNT(*) as reserved FROM cart WHERE product_id = ? GROUP BY product_id) c
            ON
                p.id = c.product_id
            WHERE
                p.id = ?
        """
        product = conn.execute(product_query, (product_id, product_id)).fetchone()
        if not product:
            return redirect(url_for('shop'))
        return render_template("product_detail.html", product=product)
    finally:
        conn.close()

@app.route("/add_to_cart/<int:product_id>")
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    try:
        product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
        if not product:
            return redirect(url_for('shop'))
        cart_quantity_row = conn.execute('SELECT COUNT(*) as quantity FROM cart WHERE user_id = ? AND product_id = ?', (session['user_id'], product_id)).fetchone()
        cart_quantity = cart_quantity_row['quantity'] if cart_quantity_row else 0
        if cart_quantity >= product['quantity']:
            return redirect(url_for('shop'))
        conn.execute('INSERT INTO cart (user_id, product_id) VALUES (?, ?)', (session['user_id'], product_id))
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for('shop'))

@app.route("/view_cart")
def view_cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    try:
        cart_items = conn.execute('''
            SELECT p.id, p.name, p.price, p.image, COUNT(c.id) as quantity
            FROM cart c
            JOIN products p ON p.id = c.product_id
            WHERE c.user_id = ?
            GROUP BY p.id, p.name, p.price, p.image
        ''', (session['user_id'],)).fetchall()
        total = sum(item['price'] * item['quantity'] for item in cart_items)
        return render_template("cart.html", cart_items=cart_items, total=total)
    finally:
        conn.close()

@app.route("/checkout")
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    try:
        user = conn.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user:
            return redirect(url_for('login'))
        cart_items = conn.execute('''
            SELECT p.id, p.name, p.price, p.image, COUNT(c.id) as quantity
            FROM cart c
            JOIN products p ON p.id = c.product_id
            WHERE c.user_id = ?
            GROUP BY p.id, p.name, p.price, p.image
        ''', (session['user_id'],)).fetchall()
        for item in cart_items:
            product = conn.execute('SELECT quantity FROM products WHERE id = ?', (item['id'],)).fetchone()
            if product['quantity'] < item['quantity']:
                return redirect(url_for('view_cart'))
        total = sum(item['price'] * item['quantity'] for item in cart_items)
        cursor = conn.execute('INSERT INTO orders (user_id, total_amount) VALUES (?, ?)', (session['user_id'], total))
        order_id = cursor.lastrowid
        for item in cart_items:
            conn.execute('''
                INSERT INTO order_items (order_id, product_id, quantity, price_at_time)
                VALUES (?, ?, ?, ?)
            ''', (order_id, item['id'], item['quantity'], item['price']))
            conn.execute('UPDATE products SET quantity = quantity - ? WHERE id = ?', (item['quantity'], item['id']))
        conn.execute('DELETE FROM cart WHERE user_id = ?', (session['user_id'],))
        conn.commit()
        return render_template("receipt.html", cart_items=cart_items, total=total, username=user['username'], order_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    finally:
        conn.close()

@app.route("/order_history")
def order_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    try:
        orders = conn.execute('''
            SELECT o.*, 
                   GROUP_CONCAT(p.name || ' (x' || oi.quantity || ')') as items
            FROM orders o
            JOIN order_items oi ON o.id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            WHERE o.user_id = ?
            GROUP BY o.id
            ORDER BY o.order_date DESC
        ''', (session['user_id'],)).fetchall()
        return render_template("order_history.html", orders=orders)
    finally:
        conn.close()

@app.route("/remove_from_cart/<int:product_id>")
def remove_from_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    try:
        conn.execute('''
            DELETE FROM cart 
            WHERE user_id = ? AND product_id = ? 
            AND id = (
                SELECT id FROM cart 
                WHERE user_id = ? AND product_id = ? 
                LIMIT 1
            )
        ''', (session['user_id'], product_id, session['user_id'], product_id))
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for('view_cart'))

@app.route("/remove_all_from_cart")
def remove_all_from_cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    try:
        conn.execute('DELETE FROM cart WHERE user_id = ?', (session['user_id'],))
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for('view_cart'))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
