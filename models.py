from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    total_logins = db.Column(db.Integer, default=0)
    total_failures = db.Column(db.Integer, default=0)
    blocked = db.Column(db.Boolean, default=False)
