from flask import Flask, render_template, request, jsonify, session, redirect
from pymongo import MongoClient
from werkzeug.utils import secure_filename # 파일 이름에 사용할 수 없는 특수 문자를 제거하여 안전한 파일 이름을 생성하는 유틸리티 함수
from bson.objectid import ObjectId
from datetime import datetime
import bcrypt
import os # 파일 경로 처리와 파일 삭제 등을 위한 모듈

app = Flask(__name__)

# 보안 강화를 위해 환경 변수에서 불러오기 (권장)
app.secret_key = os.environ.get("SECRET_KEY", "default_secret_key")

# 세션 사용자의 상태를 유지하기 위해 클라이언트(브라우저)의 쿠키에 데이터를 저장하는 방식
# app.secret_key를 사용해 암호화된 서명을 쿠키에 저장
# 세션 유지 시간은 브라우저를 닫으면 알아서 로그아웃 되게끔 설정 (기본값)

UPLOAD_FOLDER = "./static/uploads"  # 파일을 저장할 경로 변수
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # 파일을 저장할 경로 설정

client = MongoClient("mongodb+srv://skcy151515:IyuTp1jwPnkfLXXl@cluster0.es5up.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true")
db = client.dbmemo2

# 렌더링 부분
@app.route('/')
def home():
    if 'userid' in session:  # 로그인 상태 확인
        return render_template('home.html')
    return render_template('index.html')
@app.route('/home')
def user_home():
    if 'userid' in session:  # 로그인 상태 확인
        return render_template('home.html')
    return redirect('/')

@app.route('/postH')
def user_post():
    return render_template('post.html')

@app.route('/sign_up')
def sign_up():
    return render_template('sign_up.html')

@app.route('/post/<postid>')
def show_post():
    return render_template('post_show.html')

# 회원가입
@app.route('/signup', methods=['POST'])
def signup():
    # data: { userid: userid, password: password, name: name, email: email } 형식으로 데이터 불러옴
    userid = request.form['userid']
    password = request.form['password']
    name = request.form['name']
    email = request.form['email']
    
    # 기존 사용자 확인
    if db.Users.find_one({"userid": userid}):
        return jsonify({"msg": "이미 존재하는 아이디입니다."})
    if db.Users.find_one({"email" : email}):
        return jsonify({"msg": "이미 존재하는 이메일입니다."})
    
    # 비밀번호 해싱 (bcrypt 사용)
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # 데이터 저장
    db.Users.insert_one({"userid": userid, "password": hashed_pw, "name": name, "email":email})
    return jsonify({"result": "success", "msg": "회원가입 성공!"})

# 로그인
@app.route('/login', methods=['POST'])
def login():
    # data: { userid: userid, password: password } 형식으로 데이터 불러옴
    userid = request.form['userid']
    password = request.form['password']

    user = db.Users.find_one({"userid": userid})

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):  # 비밀번호 비교
        session['userid'] = userid  # 세션 저장
        return jsonify({"result": "success", "msg": "로그인 성공!"})
    else:
        return jsonify({"result": "fail", "msg": "아이디 또는 비밀번호가 틀렸습니다."})

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('userid', None)  # 세션 삭제
    return jsonify({"msg": "로그아웃 되었습니다."})

# 게시물 작성
@app.route('/post', methods=['POST'])
def uploadPost():
    if 'userid' not in session:
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'})

    # 파일과 제목, 내용을 담음
    file = request.files.get('file')  # 파일이 없을 경우 None 반환
    title = request.form['title']
    content = request.form['content']
    author = session['userid']  # 세션에서 사용자 ID 가져오기

    filename = None
    isimage = False
    extension = None

    if file:
        # secure_filename(): 특수 문자 제거
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename) # 경로 지정 ex) ./static/uploads/image.jpg

        # 파일 이름이 이미 존재하는지 확인
        while os.path.exists(file_path):
            name, extension = os.path.splitext(filename) # splitext()는 파일 경로 또는 파일 이름을 확장자와 그 외 부분으로 나누는 함수 ex) name = image, extension =.img
            filename = f"{name}s{extension}"  # 이름 뒤에 's'를 추가하여 새 파일명 생성
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        file.save(file_path)

        extension = filename.rsplit('.', 1)[-1].lower()
        isimage = extension in {'png', 'jpg', 'jpeg', 'gif', 'webp'}

    # MongoDB에 데이터 삽입
    formData = {
        'postid': str(ObjectId()),
        'file': f"/static/uploads/{filename}" if filename else None,  # 파일이 없으면 None
        'title': title,
        'content': content,
        'author': author,
        'isimage': isimage,  # 이미지 여부 추가
        'createdat': datetime.now(),
        'updatedat': datetime.now()
    }
    db.Posts.insert_one(formData)

    return jsonify({'result': 'success'})
    
# 모든 게시글 목록 조회
@app.route('/posts', methods=['GET'])
def get_posts():
    posts = list(db.Posts.find({}, {'_id': 0}))  # 모든 게시글 가져오기
    return jsonify({"result": "success", "posts": posts})

# 특정 게시글 조회
@app.route('/post/<postid>', methods=['GET'])
def get_post(postid):
    # 게시글 찾기
    post = db.Posts.find_one({"postid": postid}, {"_id": 0})  # _id 제외
    if not post:
        return jsonify({"status": "fail", "message": "해당 게시글을 찾을 수 없습니다."}), 404
    
    # 해당 게시글의 댓글 찾기
    comments = list(db.Comments.find({"postid": postid}, {"_id": 0}))

    # 응답 데이터 구성
    response = {
        "status": "success",
        "message": "게시글과 댓글을 성공적으로 조회했습니다.",
        "data": {
            "post": post,
            "comments": comments
        }
    }

    return jsonify(response), 200

# 댓글 작성
@app.route('/comment', methods=['POST'])
def add_comment():
    if 'userid' not in session:
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'})
    
    postid = request.get("postid")
    content = request.form("content")
    author = session['userid']
    
    # 댓글 데이터 생성
    comment = {
        "postid": postid,
        "content": content,
        "author": author
    }

    # MongoDB에 댓글 저장
    db.Comments.insert_one(comment)

    return jsonify({"result": "success", "message": "댓글이 작성되었습니다."}), 201


if __name__ == '__main__':
    app.run(debug=True)

