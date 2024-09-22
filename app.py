from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import g
from datetime import datetime
import sqlite3
from pathlib import Path

DATABASE_PATH = Path(__file__).parent.resolve() / "databases" / "event_calendar.db"

app = Flask(__name__)
app.secret_key = 'your_secret_key' 


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

#  Connection establish
def get_db():
    if 'db' not in g:
        try:
            g.db = sqlite3.connect(DATABASE_PATH)
            g.db.row_factory = sqlite3.Row
            
            cursor = g.db.execute('SELECT SQLITE_VERSION()')
            db_version = cursor.fetchone()[0]
            print(f"Established SQLite Database Connection. Version: {db_version}")
        except sqlite3.Error as error:
            print(f"Error while connecting to SQLite: {error}")

    return g.db


class User(UserMixin):
    def __init__(self, id, username, password, is_admin):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = is_admin

    def set_password(self, password):
        self.password = password  

    def check_password(self, password):
        return self.password == password



@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        return User(id=user['id'], username=user['username'], password=user['password'], is_admin=user['is_admin'])
    return None


@app.route('/login', methods=['GET', 'POST']) #/Login
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and user['password'] == password:  
            user_obj = User(id=user['id'], username=user['username'], password=user['password'], is_admin=user['is_admin'])
            login_user(user_obj)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')



@app.route('/logout') #/logout
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/secure-route') #/secure-route
@login_required
def secure_route():
    return render_template('secure_template.html')
    

@app.route('/admin') #/admin
@login_required
def admin():
    if not current_user.is_admin:
        flash('Geen toegang: Alleen voor admins.')
        return redirect(url_for('home'))
    
    users = query_all_users()
    return render_template('admin.html', users=users)



@app.route('/create_user', methods=['POST']) #/create_user
@login_required
def create_user():
    if not current_user.is_admin:
        return 'Unauthorized', 401

    username = request.form['username']
    password = request.form['password']  
    is_admin = 'is_admin' in request.form

    conn = get_db()
    conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                 (username, password, is_admin))  
    conn.commit()

    return redirect(url_for('admin'))



@app.route('/delete_user/<int:user_id>', methods=['POST']) #/delete_user
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return 'Unauthorized', 401

    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()

    return redirect(url_for('admin'))


@app.route('/') #/Home_page
@login_required
def home():
    agendas = query_agendas()  
    return render_template('index.html', agendas=agendas)


@app.route('/agenda/<url_name>')  # agenda_page
@login_required
def agenda(url_name):
    if current_user.is_admin:
        agenda = query_agenda_by_name(url_name)
    else:
        agenda = query_agenda_by_name_for_user(url_name, current_user.id)

    if agenda is None or (not current_user.is_admin and agenda['user_id'] != current_user.id):
        flash('Agenda not found or you do not have permission to view it.')
        return redirect(url_for('home'))

    date_filter = request.args.get('date_filter')
    location_filter = request.args.get('location_filter')
    
    limit = 20
    offset = int(request.args.get('offset', 0))
    
    events = query_filtered_events(agenda_id=agenda['id'], date_filter=date_filter, location_filter=location_filter, limit=limit, offset=offset)

    message = session.pop('message', None) if 'message' in session else None
    
    return render_template('agenda.html', agenda=agenda, events=events, offset=offset, limit=limit, message=message)




@app.route('/event/<int:event_id>') #/events_page
@login_required
def event(event_id):
    event = query_event_by_id(event_id)
    if event is None:
        return render_template('error.html', message='Event not found.')
    
    agenda = query_agenda_by_id(event['agenda_id'])  
    if agenda is None:
        return render_template('error.html', message='Agenda not found.')

    return render_template('event.html', event=event, agenda=agenda)



@app.route('/event/edit/<int:event_id>', methods=['GET', 'POST']) #/ edit_event
@login_required
def edit_event(event_id):
    event = query_event_by_id(event_id)
    if event is None:
        flash('Event not found.')
        return redirect(url_for('home'))
    
    agenda = query_agenda_by_id(event['agenda_id'])
    if agenda['user_id'] != current_user.id and not current_user.is_admin:
        flash('You are not authorized to edit this event.')
        return redirect(url_for('agenda', url_name=agenda['url_name']))
    
    if request.method == 'POST':
        name = request.form['name']
        event_date = request.form['event_date']
        start_time = request.form['start_time']
        end_time = request.form['end_time']
        location = request.form['location']
        description = request.form['description']
        
        conn = get_db()
        conn.execute('UPDATE events SET name=?, event_date=?, start_time=?, end_time=?, location=?, description=? WHERE id=?',
                     (name, event_date, start_time, end_time, location, description, event_id))
        conn.commit()
        flash('Event updated successfully.')
        return redirect(url_for('agenda', url_name=agenda['url_name']))
    
    return render_template('edit_event.html', event=event, agenda=agenda)



@app.route('/event/delete/<int:event_id>', methods=['POST']) #/delete_event
@login_required
def delete_event(event_id):
    conn = get_db()
    conn.execute('DELETE FROM events WHERE id=?', (event_id,))
    conn.commit()
    flash('Event deleted successfully.')

    return redirect(url_for('home'))



@app.route('/agenda/new', methods=['GET', 'POST']) #/new_agenda
@login_required
def new_agenda():
    if request.method == 'POST':
        url_name = request.form['url_name']
        title = request.form['title']
        style_sheet_url = request.form.get('external_stylesheet', None)  
        user_id = current_user.id  

        conn = get_db()
        conn.execute('INSERT INTO agendas (url_name, title, external_stylesheet, user_id) VALUES (?, ?, ?, ?)',
                     (url_name, title, style_sheet_url, user_id))
        conn.commit()

        return redirect(url_for('home'))
    
    return render_template('new_agenda.html')


@app.route('/agenda/<url_name>/event/new', methods=['GET', 'POST']) #/new_event
@login_required
def new_event(url_name):
    agenda = query_agenda_by_name(url_name)
    if not agenda:
        return render_template('error.html', message='Agenda not found.')
    
    if request.method == 'POST':
        name = request.form['name']
        event_date = request.form['event_date']
        start_time = request.form['start_time']
        end_time = request.form['end_time']
        location = request.form['location']
        description = request.form['description']
        
        conn = get_db()
        conn.execute('INSERT INTO events (agenda_id, name, event_date, start_time, end_time, location, description) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (agenda['id'], name, event_date, start_time, end_time, location, description))
        conn.commit()

        return redirect(url_for('agenda', url_name=url_name))
    
    return render_template('new_event.html', agenda=agenda)


@app.template_filter('dateformat') #/date_format
def dateformat_filter(value, format='%d %B, %Y'):
    if value is None:
        return ""
    return datetime.strptime(value, '%Y-%m-%d').strftime(format)

app.jinja_env.filters['dateformat'] = dateformat_filter


def query_agendas():
    conn = get_db()
    cursor = conn.cursor()

    if current_user.is_admin:
        query = "SELECT * FROM agendas;"
        cursor.execute(query)
    else:
        query = "SELECT * FROM agendas WHERE user_id = ?;"
        cursor.execute(query, (current_user.id,))

    agendas = cursor.fetchall()
    return agendas

def query_agenda_by_name(url_name):
    query = "SELECT * FROM agendas WHERE url_name = ?;"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query, (url_name,))
    agenda = cursor.fetchone()
    return agenda

def query_filtered_events(agenda_id, date_filter, location_filter, limit, offset):
    db = get_db()
    query = """
    SELECT * FROM events 
    WHERE agenda_id = ? 
    """
    params = [agenda_id]

    if date_filter:
        query += " AND date(event_date) = ?"
        params.append(date_filter)
    if location_filter:
        query += " AND location LIKE ?"
        params.append(f"%{location_filter}%")
    
    query += " LIMIT ? OFFSET ?"
    params.append(limit)
    params.append(offset)

    events = db.execute(query, params).fetchall()
    return events

def query_agenda_by_name_for_user(url_name, user_id):
    db = get_db()
    query = "SELECT * FROM agendas WHERE url_name = ?" + ("" if user_id is None else " AND user_id = ?")
    args = (url_name,) if user_id is None else (url_name, user_id)
    agenda = db.execute(query, args).fetchone()
    return agenda

def query_upcoming_events(agenda_id, limit=20, offset=0):
    query = """
    SELECT id, name, event_date, start_time, end_time, location
    FROM events
    WHERE agenda_id = ? AND event_date > DATE('now')
    ORDER BY event_date ASC
    LIMIT ? OFFSET ?;
    """
    conn = get_db()
    c = conn.cursor()
    c.execute(query, (agenda_id, limit, offset))
    return c.fetchall()

def query_agenda_by_id(agenda_id):
    db = get_db()
    return db.execute("SELECT * FROM agendas WHERE id = ?", (agenda_id,)).fetchone()

def query_event_by_id(event_id):
    db = get_db()
    event = db.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    return event

def query_all_users():
    conn = get_db()
    users = conn.execute('SELECT * FROM users').fetchall()
    return users

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


if __name__ == '__main__':
    app.run(debug=True)

