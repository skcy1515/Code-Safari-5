from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"  # 세션을 위한 키 설정

client = MongoClient("mongodb+srv://skcy151515:IyuTp1jwPnkfLXXl@cluster0.es5up.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true")
db = client.dbmemo2

@app.route('/')
def home():
    if 'user_id' in session:  # 로그인 상태 확인
        return render_template('home.html')
    return render_template('index.html')
@app.route('/home')
def user_home():
    if 'user_id' in session:  # 로그인 상태 확인
        return render_template('home.html')
    return redirect('/')

@app.route('/signup', methods=['POST'])
def signup():
    userid = request.form['userid']
    password = request.form['password']
    
    # 기존 사용자 확인
    if db.Users.find_one({"user_id": userid}):
        return jsonify({"msg": "이미 존재하는 아이디입니다."})
    
    # 비밀번호 해싱 (bcrypt 사용)
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # 데이터 저장
    db.Users.insert_one({"user_id": userid, "password": hashed_pw})
    return jsonify({"msg": "회원가입 성공!"})


@app.route('/login', methods=['POST'])
def login():
    userid = request.form['userid']
    password = request.form['password']

    user = db.Users.find_one({"user_id": userid})

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):  # 평문 비교
        session['user_id'] = userid  # 세션 저장
        return jsonify({"result": "success", "message": "로그인 성공!"})
    else:
        return jsonify({"result": "fail", "msg": "아이디 또는 비밀번호가 틀렸습니다."})

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # 세션 삭제
    return jsonify({"msg": "로그아웃 되었습니다."})

if __name__ == '__main__':
    app.run(debug=True)

