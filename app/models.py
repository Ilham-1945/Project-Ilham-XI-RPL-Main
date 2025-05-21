from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_accepted = db.Column(db.Boolean, default=None)
    formulir = db.relationship('Formulir', backref='user', lazy=True, uselist=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Formulir(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nama = db.Column(db.String(100), nullable=False)
    tempat_lahir = db.Column(db.String(100), nullable=False)
    tanggal_lahir = db.Column(db.Date, nullable=False)
    alamat = db.Column(db.String(200), nullable=False)
    asal_sekolah = db.Column(db.String(100), nullable=False)
    kelamin = db.Column(db.String(1), nullable=False)  # 'L' atau 'P'
    agama = db.Column(db.String(20), nullable=False)
    jurusan = db.Column(db.String(10), nullable=False)
    nilai_rata = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='pending')  # Add this line
    ijazah_filename = db.Column(db.String(200))  # nama file ijazah yang diupload
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())