from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "userdetails"
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.String(100),unique = True)
    username = db.Column(db.String(20), unique = True, nullable = False)
    email_address = db.Column(db.String(60), unique = True, nullable = False)
    password = db.Column(db.String(200), nullable = False)
    age = db.Column(db.Integer, nullable = False)
    gender = db.Column(db.String(20), nullable = False)
    created_at = db.Column(db.DateTime)
    otp = db.Column(db.String(16))
    otp_expire = db.Column(db.DateTime)

    def __init__(self, user_id, username, email, password, gender, created_at, age):
        self.user_id = user_id
        self.username = username
        self.email_address = email
        self.password = password
        self.gender = gender
        self.age = age
        self.created_at = created_at
    
    def __str__(self):
        return self.username

class BmiData(db.Model):
    __tablename__ = "bmidata"
    id =  db.Column(db.Integer, primary_key = True)
    height = db.Column(db.Float, nullable = False)
    weight = db.Column(db.Float, nullable = False)
    bmi = db.Column(db.Float, nullable = False)
    measured_at = db.Column(db.DateTime)
    userid = db.Column(db.String(100), db.ForeignKey('userdetails.user_id',ondelete="CASCADE"), nullable=False)

    def __init__(self, height, weight, bmi, measured_at, userid):
        self.height = height
        self.weight = weight
        self.bmi = bmi
        self.measured_at = measured_at
        self.userid = userid

    def __str__(self):
        return str(self.bmi)