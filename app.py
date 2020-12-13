from flask import Flask, render_template, request, redirect, url_for,make_response,abort,send_file
from werkzeug.security import generate_password_hash,check_password_hash
from sqlalchemy.sql import func

from email_data import send_otp, send_bmidata_tomail, send_signup_email_verification
from utilities import stringify_datetime, status_of_bmi, analyze_health, generate_otp
from models import db, User, BmiData

import datetime, jwt, csv, uuid, json
from functools import wraps

from google.oauth2 import id_token
from google.auth.transport import requests

import configparser
config = configparser.ConfigParser()
config.read(r"..\confidential.ini")

app = Flask(__name__)
app.config["SECRET_KEY"] = config["DEFAULT"]["jwt-secret-key"]
app.config["CLIENT_ID"] = config["Google_signin"]['google-signin-client-id']
app.config["SQLALCHEMY_DATABASE_URI"] = config["Postgresql"]["localserver_uri"] #{this is for offline sql}
# app.config["SQLALCHEMY_DATABASE_URI"] = config["Postgresql"]["awsserver_uri"]
db.init_app(app)

def create_db():
    db.create_all(app = app)
    """   
        ----or----
    with app.app_context():
        db.create_all()      
    """


def token_required(func):
    @wraps(func)
    def check_login_status(*args,**kwargs):
        token = None
        if 'gOauth_authorisation' in request.cookies:
            token = request.cookies['gOauth_authorisation']
            CLIENT_ID = app.config["CLIENT_ID"]
            try:
                idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)
                current_user = User.query.filter_by(email_address = idinfo["email"]).first()
            except ValueError:
                return redirect(url_for('authpage'))
            except:
                abort(401, description="Unauthorized access token")
            else:
                return func(current_user, *args, **kwargs)

        if 'jwt_authorisation' in request.cookies:
            token = request.cookies['jwt_authorisation']
            try:
                data = jwt.decode(token,app.config['SECRET_KEY'])
                current_user = User.query.filter_by(user_id = data['user_id']).first()
            except ValueError:
                return redirect(url_for('authpage'))
            except:
                abort(401, description="Unauthorized access token")
            else:
                return(func(current_user,*args,**kwargs))

        if token == None:
            return redirect(url_for('authpage'))

    return check_login_status

@app.route("/")
def authpage():
    response = make_response(render_template("authpage.html"))
    if 'gOauth_authorisation' in request.cookies:
        response.delete_cookie('gOauth_authorisation')
    if 'jwt_authorisation' in request.cookies:
        if 'keepMeLoggedIn' in request.cookies:
            return redirect('home')
        else:
            response.delete_cookie('jwt_authorisation')
    return response

@app.route("/login", methods=['POST'])
def login():
    
    email_address = request.form["email"].strip()
    password = request.form["password"].strip()
    user_info = User.query.filter_by(email_address = email_address).first()

    if user_info != None and check_password_hash(user_info.password, password):
        response = make_response(redirect(url_for('user_homepage')))

        if 'keepMeLoggedIn' in request.form.keys():
            token = jwt.encode({'user_id' : user_info.user_id, 'exp' : datetime.datetime.now() + datetime.timedelta(hours = 400)}, app.config['SECRET_KEY'])
            response.set_cookie('keepMeLoggedIn', 'on')
        else:
            token = jwt.encode({'user_id' : user_info.user_id, 'exp' : datetime.datetime.now() + datetime.timedelta(minutes = 40)}, app.config['SECRET_KEY'])

        response.set_cookie('jwt_authorisation',token)
        return response
    else:
        return render_template("authpage.html", loginError = "The Email-ID or Password you entered is incorrect!, Kindly try again..")        

@app.route("/signup-success", methods=['POST'])
def signup():
    user_id = str(uuid.uuid4())
    username = request.form["username"].strip()
    email_address = request.form["email"].strip()
    age = request.form["age"]
    gender = request.form["gender"]

    if 'continue_signup_with_token' in request.cookies:
        token = request.cookies['continue_signup_with_token']
        if User.query.filter_by(username = username).first() == None:
            response = make_response(redirect(url_for('user_homepage')))
            response.set_cookie('gOauth_authorisation', token)
            response.delete_cookie('continue_signup_with_token')
            hashed_password = generate_password_hash(request.form['password'], method='sha256')
        else:
            response = make_response(redirect(url_for('create_account')))
            response.set_cookie('username_exists_error_with_token', token)
            response.delete_cookie('continue_signup_with_token')
            return response

    elif 'hashed_otp' in request.form.keys():
        hashed_otp = request.form['hashed_otp']
        if check_password_hash(hashed_otp, request.form['email_verification_otp'].strip()):
            hashed_password = request.form['hashed_password']
            signupSuccess="Your account has been created successfully, Log in to your account <3"
            response = make_response(render_template("authpage.html", 
                                                    response_from = "login", 
                                                    signupSuccess = signupSuccess)
                                    )
        else:
            response = make_response("Unauthorized access (ERROR - 401)", 401)
            return response
    else:
        response = make_response("Unauthorized access (ERROR - 401)", 401)
        return response

    userentry = User(user_id,username,email_address,hashed_password,gender,created_at=datetime.datetime.now(),age=age)
    db.session.add(userentry)
    db.session.commit()

    return response

@app.route("/signup/check-signup", methods=['POST'])
def signup_check():
    username = request.form["username"].strip()
    email_address = request.form["email"].strip()

    if User.query.filter_by(email_address = email_address).count() != 0:
        signupError = "The Email-ID you entered is already exist, try logging in !!"
        return render_template("authpage.html", response_from = "signup", signupError = signupError)

    if User.query.filter_by(username = username).count() != 0:
        signupError = "The username you entered is already exist, try another!!"
        return render_template("authpage.html", response_from = "signup", signupError = signupError)

    hashed_password = generate_password_hash(request.form['password'], method='sha256')
    age = request.form["age"]
    gender = request.form["gender"]
    otp =  generate_otp()
    hashed_otp = generate_password_hash(otp, method='sha256')

    user_details = {'username': username,
                    'email_address': email_address,
                    'hashed_password': hashed_password,
                    'age': age,
                    'gender': gender,
                    'hashed_otp': hashed_otp}

    send_signup_email_verification(email_address, otp)
    return render_template("authpage.html", response_from = "signup", user_details=user_details, from_signup_check="true")

@app.route("/google-signin", methods=['POST'])
def google_signin():
    try:
        token = request.form['idtoken']
        CLIENT_ID = app.config["CLIENT_ID"]
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)
        user_registered = User.query.filter_by(email_address = idinfo['email']).first()
        response = make_response()

        if user_registered == None:
            response.headers['redirect_url'] = url_for('create_account')
            response.set_cookie('create_account_with_token', token)
        else:
            response.headers['redirect_url'] = url_for('user_homepage')
            response.set_cookie('gOauth_authorisation',token)

    except ValueError: 
        return abort(404)
    else:
        return response

@app.route("/create-account/")
def create_account():
    CLIENT_ID = app.config["CLIENT_ID"]
    
    if 'create_account_with_token' in request.cookies:
        account_creation_token = request.cookies['create_account_with_token']
        try:
            idinfo = id_token.verify_oauth2_token(account_creation_token, requests.Request(), CLIENT_ID)
            user_email = idinfo["email"]
            response = make_response(render_template("createAccount.html",user_email = user_email))
            response.delete_cookie('create_account_with_token')
        except:
            abort(401, description="your token is not authorized")
    
    
    elif 'username_exists_error_with_token' in request.cookies:
        account_creation_token = request.cookies['username_exists_error_with_token']
        errormsg = "The username you entered is already exist, try another!!"
        try:
            idinfo = id_token.verify_oauth2_token(account_creation_token, requests.Request(), CLIENT_ID)
            user_email = idinfo["email"]
            response = make_response(render_template("createAccount.html",
                                                user_email = user_email,
                                                errormsg = errormsg,
                                                ),
                                )
            response.delete_cookie('username_exists_error_with_token')
        except:
            abort(401, description="your token is not authorized")
    
    else:
        abort(401, description="Unauthorized entry")

    response.set_cookie('continue_signup_with_token',account_creation_token)
    return response

@app.route("/home")
@token_required
def user_homepage(current_user):
    return render_template("userHomepage.html", user=current_user)

@app.route("/reset-password", methods=['GET','POST'])
def reset_password():
    errormsg = ''

    if request.method == 'POST':
        email = request.form['email'].strip()
        resetting_user = User.query.filter_by(email_address = email).first()

        if resetting_user != None:
            otp = generate_otp()
            expire = datetime.datetime.now() + datetime.timedelta(minutes=4)
            resetting_user.otp = otp
            resetting_user.otp_expire = expire
            db.session.commit()
            send_otp(otp = otp, requested_mail = resetting_user.email_address)
            return render_template("resetPassword.html",success = True, user = resetting_user, errormsg =errormsg)
        else:
            errormsg = "Entered wrong email or You haven't registered, Kindly check again !!"

    return render_template("resetPassword.html", success = False, errormsg =errormsg)

@app.route("/Check_otp", methods=['POST'])
def check_otp():
    email = request.form['email_address'].strip()
    otp = request.form['otp'].strip()
    resetting_user = User.query.filter_by(email_address = email).first()

    if otp == resetting_user.otp:
        if resetting_user.otp_expire > datetime.datetime.now():
            return render_template('newPassword.html', success = False, user = resetting_user)
        else:
            errormsg = "OTP has been expired ! Try again in time"
            return render_template("resetPassword.html", success = False, errormsg = errormsg, user = resetting_user) 
    else:
        errormsg = "Incorrect OTP ! Try again !!"
        return render_template("resetPassword.html",success = True, user = resetting_user, errormsg = errormsg)

@app.route("/new-password", methods = ['POST'])
def new_password():
    email = request.form['email_address'].strip()
    newpassword = request.form['newpassword'].strip()
    cnfpassword = request.form['cnfpassword'].strip()
    if ( 8 <= len(newpassword) <= 15 ) and ( 8 <= len(cnfpassword) <= 15 ):
        resetting_user = User.query.filter_by(email_address = email).first()
        errormsg = ''
        success = True
    else:
        errormsg = 'Length of password should be between 8 and 15'
        success = False
    
    resetting_user = User.query.filter_by(email_address = email).first()
    resetting_user.password = generate_password_hash(newpassword, method='sha256')
    db.session.commit()
    
    return render_template('newPassword.html', success=success, user = resetting_user, errormsg=errormsg)

@app.route("/bmipage")
@token_required
def bmi_page(current_user):
    return render_template("bmiPage.html", user=current_user)

@app.route("/visiontestpage")
@token_required
def visiontest_page(current_user):
    return render_template("visionTestPage.html", user=current_user)

@app.route("/healthcheckpage")
@token_required
def healthcheck_page(current_user):
    return render_template("healthCheckPage.html", user=current_user)

@app.route("/healthcheckanalyze", methods =["POST"])
@token_required
def healthcheck_analyze(current_user):
    user_answers = request.form
    user_results = analyze_health(user_answers)
    return render_template('healthCheckResults.html', user_results = user_results, user=current_user)

@app.route("/bmi-success", methods=['POST'])
@token_required
def bmi_success(current_user):
    weight = request.form["weight"]
    height = request.form["height"]

    bmi = ( float(weight) / (float(height)/100)**2 )
    bmi = round(bmi, 1)

    if 'save' in request.form:
        save_result = request.form["save"]
        if save_result == "True":
            bmi_result = BmiData(height, weight, bmi, 
                                measured_at = datetime.datetime.now(),
                                userid = current_user.user_id,
                                )
            db.session.add(bmi_result)
            db.session.commit()

    # status_of_bmi function returns status and a pic
    status, status_pic = status_of_bmi(bmi)

    bmi_data = {"bmi":bmi, "status":status, "visual":status_pic }

    return render_template("bmiSuccess.html", BMI_data = bmi_data, user=current_user)

@app.route("/download_result")
@token_required
def download_result(current_user):

    bmi_list = BmiData.query.filter_by(userid = current_user.user_id).all()
    if bmi_list != []:
        file_name = current_user.username + '.csv'
        with open('bmi_result.csv', 'w') as user_bmi_report:
            csv_file = csv.writer(user_bmi_report)
            count = 0
            csv_file.writerow([ 'S.No',
                                'Measured Date', 
                                'Measured Time', 
                                'Height', 
                                'Weight', 
                                'BMI', 
                                'BMI status'])
            for bmi_data in bmi_list:
                count += 1
                date, time = stringify_datetime(bmi_data.measured_at)
                csv_file.writerow([ count,
                                    date,
                                    time,
                                    bmi_data.height,
                                    bmi_data.weight,
                                    bmi_data.bmi,
                                    status_of_bmi(bmi_data.bmi)[0],
                                ])
        return send_file('bmi_result.csv', attachment_filename = file_name, as_attachment=True, cache_timeout = 0 )
    else:
        error = "You haven't saved any BMI for processing"
        return render_template('bmiSuccess.html', errormsg = error, username = current_user.username)

@app.route("/email_result")
@token_required
def email_result(current_user):
    try:
        bmi_list = BmiData.query.filter_by(userid = current_user.user_id).all()

        if bmi_list == []:
            response_text = "You haven't saved any BMI for processing"
        else:
            with open('bmi_result.csv', 'w') as user_bmi_file:
                csv_file = csv.writer(user_bmi_file)
                count = 0
                csv_file.writerow([ 'S.No',
                                    'Measured Date',
                                    'Measured Time',
                                    'Height',
                                    'Weight',
                                    'BMI',
                                    'BMI status'])
                for bmi_data in bmi_list:
                    count += 1
                    date, time = stringify_datetime(bmi_data.measured_at)
                    csv_file.writerow([ count,
                                        date,
                                        time,
                                        bmi_data.height,
                                        bmi_data.weight,
                                        bmi_data.bmi,
                                        status_of_bmi(bmi_data.bmi)[0],
                                    ])
            send_bmidata_tomail(to_email = current_user.email_address, 
                                bmidata_filename = 'bmi_result.csv', 
                                username = current_user.username
                                )
            response_text = "Email have been sent to you successfully"  
    except:
        response_text = "Error has occured internally, please try again later"
    return response_text

@app.route("/signout")
@token_required
def signout(current_user):
    response = make_response(redirect(url_for('authpage')))
    response.delete_cookie('jwt_authorisation')
    response.delete_cookie('gOauth_authorisation')
    response.delete_cookie('keepMeLoggedIn')
    return response

if __name__ == "__main__":
    app.run(debug=False)