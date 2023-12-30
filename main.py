# flask framework and other functions and modules to help navigate and create behaviors for the web
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
# werkzeug library for building WSGI to build web server gateway interface and security
from werkzeug.security import generate_password_hash, check_password_hash
# SQLAlchemy for building SQLite Database
from flask_sqlalchemy import SQLAlchemy
# flask_login for building user registration process
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
# storing sensitive information
import os

# Create the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("Flask_Secret_Key")

# Connect to the database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("Database_Name")
db = SQLAlchemy(app)

# Create LoginManager object to configure flask-login
login_manager = LoginManager(app)


# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(1000))


# Create tables in the database
with app.app_context():
    db.create_all()


# User loader function for flask-login
@login_manager.user_loader
def load_user(user_id):
    """
    Loads the user with the given ID for flask-login.

    :param user_id: The ID of the user to load.
    :return: User object or None if not found.
    """
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()


# Home route
@app.route('/')
def home():
    """
    Renders the home page.

    :return: Rendered HTML template.
    """
    return render_template("index.html", logged_in=current_user.is_authenticated)


# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration.

    :return: Redirects to secrets page on successful registration; otherwise, redirects to the registration page.
    """
    if request.method == 'POST':
        user_email = db.session.execute(db.select(User).where(User.email == request.form["email"])).scalar()

        if user_email is None:
            # Hash and salt the password to enhance security
            hashed_salted_password = generate_password_hash(
                password=request.form["password"],
                method="pbkdf2:sha256",
                salt_length=8
            )

            # Create a new user object
            new_user = User(
                email=request.form["email"],
                password=hashed_salted_password,
                name=request.form["name"]
            )

            # Add user to the database
            db.session.add(new_user)
            db.session.commit()

            # Log in the new user and redirect to secrets page
            login_user(new_user)
            return redirect(url_for("secrets"))
        else:
            flash("An account already exists with this email.")
            return redirect(url_for("register"))

    return render_template("register.html", logged_in=current_user.is_authenticated)


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.

    :return: Redirects to secrets page on successful login; otherwise, redirects to the login page.
    """

    # receiving submitted data from user
    if request.method == 'POST':
        user_email = request.form["email"]
        user_password = request.form["password"]
        user_object = db.session.execute(db.select(User).where(User.email == user_email)).scalar()

        if user_object is None:  # happens when cannot find object in database
            flash("That email does not exist. Please try again.")   # store message at the end of request to give feedback
            return redirect(url_for("login"))
        else:
            if check_password_hash(user_object.password, user_password):
                # Valid password, log in the user and redirect to secrets page
                login_user(user_object)
                return redirect(url_for("secrets"))
            else:
                flash("Invalid password. Please try again.")
                return redirect(url_for("login"))

    return render_template("login.html", logged_in=current_user.is_authenticated)


# Secrets route
@app.route('/secrets')
@login_required
def secrets():
    """
    Renders the secrets page, accessible only to logged-in users.

    :return: Rendered HTML template.
    """
    return render_template("secrets.html", user_name=current_user.name, logged_in=True)


# Logout route
@app.route('/logout')
def logout():
    """
    Logs out the current user.

    :return: Redirects to the home page.
    """
    logout_user()
    return redirect(url_for("home"))


# Download route
@app.route('/download', methods=['GET'])
def download():
    """
    Handles file download.

    :return: Sends the specified file for download.
    """
    return send_from_directory("static", "files/cheat_sheet.pdf", as_attachment=True)


# Run the application
if __name__ == "__main__":
    app.run(debug=True)
