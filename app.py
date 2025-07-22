# app.py
import os
from flask import Flask, render_template, redirect, url_for, flash, request, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from utils.log_parser import parse_logs, parse_log_file
from utils.geoip import get_ip_location
from utils.alerts import send_alert_email
from utils.report_generator import generate_pdf_report
# Route to download PDF report for a specific log file

from forms import LoginForm, RegisterForm
from model import db, User


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Route to download PDF report for a specific log file
@app.route('/download_pdf/<filename>')
@login_required
def download_pdf(filename):
    logs_dir = 'logs'
    file_path = os.path.join(logs_dir, filename)
    if not os.path.exists(file_path):
        flash(f'Log file {filename} not found.', 'danger')
        return redirect(url_for('upload_logs'))
    # Parse log data for the report
    log_data = parse_log_file(file_path)
    # Generate PDF (returns path to PDF file)
    pdf_path = generate_pdf_report(log_data, filename)
    if not os.path.exists(pdf_path):
        flash('Failed to generate PDF report.', 'danger')
        return redirect(url_for('show_report', filename=filename))
    # Send the PDF file for download
    return send_file(pdf_path, as_attachment=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    log_data = parse_logs('logs')
    total_logs = log_data["total_logs"]
    total_threats = log_data["total_threats"]
    unique_ips = log_data["unique_ips"]
    top_threats = log_data["top_threats"]
    ai_threats = log_data["ai_threats"]
    geo_data = log_data["geo_data"]
    status_counts = log_data["status_counts"]
    ip_counts = log_data["ip_counts"]
    timeline = log_data["timeline"]
    top_urls= log_data["top_urls"]
    top_agents = log_data["top_agents"]
    top_countries = log_data["top_countries"]
    return render_template('dashboard.html',
                           total_logs=total_logs,
                           total_threats=total_threats,
                           unique_ips=unique_ips,
                           top_threats=top_threats,
                           ai_threats=ai_threats,
                           geo_data=geo_data,
                           log_data=log_data,
                           status_counts=status_counts,
                           ip_counts=ip_counts,
                           timeline=timeline,
                           top_urls=top_urls,
                           top_agents=top_agents,
                           top_countries=top_countries,
                           enable_graphs=True)
    
@app.route('/view_result')
@login_required
def view_result():
    return render_template('results.html')

@app.route('/status_code_distribution')
@login_required
def status_code_distribution():
    log_data = parse_logs('logs')
    status_counts = log_data["status_counts"]
    return render_template('status_code_distribution.html', status_counts=status_counts)

@app.route('/top_req_ip')
@login_required
def top_req_ip():
    log_data = parse_logs('logs')
    ip_counts = log_data["ip_counts"]
    return render_template('top_req_ip.html', ip_counts=ip_counts)

@app.route('/activity_timeline')
@login_required
def activity_timeline():
    log_data = parse_logs('logs')
    timeline_data = log_data["timeline"]
    return render_template('activity_timeline.html', timeline_data=timeline_data)


@app.route('/upload_logs', methods=['GET', 'POST'])
@login_required
def upload_logs():
    logs_dir = 'logs'
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    if request.method == 'POST':
        log_file = request.files.get('log_file')
        if log_file and log_file.filename.endswith(('.log', '.txt')):
            filepath = os.path.join(logs_dir, log_file.filename)
            log_file.save(filepath)
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('upload_logs'))
        else:
            flash('Invalid file type. Please upload a .txt file.', 'danger')
            return redirect(url_for('upload_logs'))
    log_files = os.listdir(logs_dir)
    return render_template('upload_logs.html', log_files=log_files)

@app.route('/logs/<filename>')
@login_required
def view_log_file(filename):
    logs_dir = 'logs'
    return send_from_directory(logs_dir, filename)


# Route to delete a log file
@app.route('/logs/delete/<filename>', methods=['POST'])
@login_required
def delete_log_file(filename):
    logs_dir = 'logs'
    filepath = os.path.join(logs_dir, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        flash(f'File {filename} deleted successfully!', 'success')
    else:
        flash(f'File {filename} not found.', 'danger')
    return redirect(url_for('upload_logs'))


@app.route('/logs/show_report/<filename>', methods=['GET'])
@login_required
def show_report(filename):
    logs_dir = 'logs'
    file_path = os.path.join(logs_dir, filename)
    log_data=parse_log_file(file_path)
    if os.path.exists(file_path):
        total_logs = log_data["total_logs"]
        total_threats = log_data["total_threats"]
        unique_ips = log_data["unique_ips"]
        top_threats = log_data["top_threats"]
        ai_threats = log_data["ai_threats"]
        geo_data = log_data["geo_data"]
        status_counts = log_data["status_counts"]
        ip_counts = log_data["ip_counts"]
        timeline = log_data["timeline"]
        top_urls= log_data["top_urls"]
        top_agents = log_data["top_agents"]
        top_countries = log_data["top_countries"]
        threat_details = log_data["threat_details"]
        threat_ip_summary = log_data["threat_ip_summary"]
        return render_template('report_template.html', 
                                total_logs=total_logs,
                                total_threats=total_threats,
                                unique_ips=unique_ips,
                                top_threats=top_threats,
                                ai_threats=ai_threats,
                                geo_data=geo_data,
                                log_data=log_data,
                                status_counts=status_counts,
                                ip_counts=ip_counts,
                                timeline=timeline,
                                top_urls=top_urls,
                                top_agents=top_agents,
                                top_countries=top_countries,  
                                filename=filename,
                                threat_details=threat_details,
                                threat_ip_summary=threat_ip_summary,
                                date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    else:
        flash(f'Log file {filename} not found.', 'danger')
        return redirect(url_for('upload_logs'))
    

@app.route('/logs/download_report/<filename>')
@login_required
def download_log_report(filename):
    logs_dir = 'logs'
    file_path = os.path.join(logs_dir, filename)
    if not os.path.exists(file_path):
        flash(f'Log file {filename} not found.', 'danger')
        return redirect(url_for('upload_logs'))
    # Parse log data for the report
    log_data = parse_log_file(file_path)
    # Generate detailed PDF (matches HTML report)
    from utils.report_generator import generate_detailed_threat_pdf
    pdf_path = generate_detailed_threat_pdf(log_data, filename)
    if not os.path.exists(pdf_path):
        flash('Failed to generate PDF report.', 'danger')
        return redirect(url_for('show_report', filename=filename))
    # Send the PDF file for download
    return send_file(pdf_path, as_attachment=True)


# Route to show threat report for a specific log file
@app.route('/generate_report')
@login_required
def generate_report():
    log_file = request.args.get('log_file')
    logs_dir = 'logs'
    if log_file:
        file_path = os.path.join(logs_dir, log_file)
        if os.path.exists(file_path):
            # You can parse just this file or pass its name to the template
            # For now, just pass the filename
            return render_template('report_template.html', log_file=log_file)
        else:
            flash('Log file not found.', 'danger')
            return redirect(url_for('upload_logs'))
    else:
        flash('No log file specified.', 'danger')
        return redirect(url_for('upload_logs'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)