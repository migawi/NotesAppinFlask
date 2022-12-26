from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from flask_login import login_user, login_required, logout_user, current_user
from . import db
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Login was successful!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('The password is incorrect, try again.', category='invalid')
        else:
            flash('No user with such email.', category='invalid')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['POST', 'GET'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('User with that email already exists. Try another email.', category='invalid')

        elif len(email) < 5:
            flash('Email length is too short.', category='invalid')
        elif len(first_name) < 2:
            flash('A valid name need be more than 2 characters', category='invalid')
        elif password1 != password2:
            flash('Your passwords do not match.', category='invalid')
        elif len(password1) < 6:
            flash('Password should be more than or equal to 6 characters.', category='invalid')
        else:
            # add user to database
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Account created successfully.', category='success')
            return redirect(url_for('views.home'))
        
    return render_template("signup.html", user=current_user)
