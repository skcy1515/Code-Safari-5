from flask import Flask, render_template, request, jsonify, session
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

uri = "mongodb+srv://skcy151515:IyuTp1jwPnkfLXXl@cluster0.es5up.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true"
client = MongoClient(uri, 27017)  # MongoDB는 27017 포트로 돌아갑니다.
db = client.dbmemo2

# 렌더링 부분

@app.route('/sign_up')
def sign_up():
    return render_template('sign_up.html')

# 마이페이지로 이동
@app.route('/mypage')
def mypage():
    return render_template('mypage.html')

@app.route('/login')
def show_login():
    return render_template('sign_in.html')

# URL에서 postid를 받아옴
@app.route('/post/<postid>')
def show_post(postid):
    return render_template('post_show.html')

@app.route('/')
def show_main():
    return render_template('index.html')

# 게시글 작성 페이지로 이동
@app.route('/post_write')
def make_post():
    return render_template('post_write.html')

# 게시글 수정 페이지로 이동
@app.route('/post/edit/<postid>')
def edit_post(postid):  
    return render_template('post_edit.html')

# 회원 수정 페이지로 이동
@app.route('/edit/profile')
def edit_profile():  
    return render_template('edit_profile.html')

# 내 게시글 조회 페이지로 이동
@app.route('/getMyPosts')
def getMyPosts():  
    return render_template('view_post.html')

# 회원가입
@app.route('/sign_up', methods=['POST'])
def signup():
    # data: { userid: userid, password: password, name: name, email: email } 형식으로 데이터 불러옴
    # Get 요청은 args로, Post 요청은 form으로
    userid = request.form['userid']
    password = request.form['password']
    name = request.form['name']
    email = request.form['email']
    
    # 기존 사용자 확인
    if db.Users.find_one({"userid": userid}):
        return jsonify({"result": "fail", "msg": "이미 존재하는 아이디입니다."}), 400
    if db.Users.find_one({"email" : email}):
        return jsonify({"result": "fail", "msg": "이미 존재하는 이메일입니다."}), 400
    
    # 비밀번호 해싱 (bcrypt 사용)
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # 데이터 저장
    db.Users.insert_one({"userid": userid, "password": hashed_pw, "name": name, "email":email})
    return jsonify({"result": "success", "msg": "회원가입 성공!"}), 200

# 로그인
@app.route('/login', methods=['POST'])
def login():
    # data: { userid: userid, password: password } 형식으로 데이터 불러옴
    userid = request.form['userid']
    password = request.form['password']

    user = db.Users.find_one({"userid": userid})

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):  # 비밀번호 비교
        session['userid'] = userid  # 세션 저장
        return jsonify({"result": "success", "msg": "로그인 성공!"}), 200
    else:
        return jsonify({"result": "fail", "msg": "아이디 또는 비밀번호가 틀렸습니다."}), 400

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('userid', None)  # 세션 삭제
    return jsonify({"result": "success", "msg": "로그아웃 되었습니다."}), 200

# 게시글 작성
@app.route('/post', methods=['POST'])
def uploadPost():
    if 'userid' not in session:
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401

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

    return jsonify({'result': 'success', 'msg': '게시글 작성이 완료됐습니다.'}), 200
    
# 모든 게시글 목록 조회
@app.route('/posts', methods=['GET'])
def get_posts():
    posts = list(db.Posts.find({}, {'_id': 0}))  # 모든 게시글 가져오기
    return jsonify({"result": "success", "posts": posts}), 200

# 특정 게시글 조회
@app.route('/post/view/<postid>', methods=['GET'])
def get_post(postid):
    if 'userid' not in session:
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401
    
    # 게시글 찾기
    post = db.Posts.find_one({"postid": postid}, {"_id": 0})  # _id 제외
    if not post:
        return jsonify({"result": "fail", "msg": "해당 게시글을 찾을 수 없습니다."}), 400
    
    # 해당 게시글의 댓글 찾기
    comments = list(db.Comments.find({"postid": postid}, {"_id": 0}))

    # 응답 데이터 구성
    response = {
        "result": "success",
        "msg": "게시글과 댓글을 성공적으로 조회했습니다.",
        "data": {
            "post": post,
            "comments": comments            
        }
    }

    return jsonify({'result': 'success', 'response' : response}), 200

# 특정 게시글 조회 (수정할 때)
@app.route('/post/editPost/<postid>', methods=['GET'])
def get_post_edit(postid):
    if 'userid' not in session:
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401
    
    # 게시글 찾기
    post = db.Posts.find_one({"postid": postid}, {"_id": 0})  # _id 제외
    if not post:
        return jsonify({"result": "fail", "msg": "해당 게시글을 찾을 수 없습니다."}), 400
    
    # 게시글 작성자와 로그인한 사용자가 일치하는지 확인
    userid = session['userid']
    if post.get("author") != userid:
        return jsonify({"result": "fail", "msg": "작성자만 수정할 수 있습니다."}), 403
    
    # 응답 데이터 
    return jsonify({
        "result": "success",
        "msg": "게시글을 성공적으로 조회했습니다.",
        "post": post
    }), 200

# 댓글 작성
@app.route('/post/<postid>/comment', methods=['POST'])
def add_comment(postid):
    if 'userid' not in session:
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401
    
    content = request.form.get("content")

    # 댓글 데이터 생성
    comment = {
        "postid": postid,
        "content": content
    }

    # MongoDB에 댓글 저장
    db.Comments.insert_one(comment)

    return jsonify({"result": "success", "msg": "댓글이 작성되었습니다.", 'content' : content}), 200


# 마이페이지
@app.route('/get_mypage', methods=['GET'])
def get_user_info():
    if 'userid' not in session:  # 로그인 확인
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401
    
    userid = session['userid']  # 세션에서 사용자 ID 가져오기
    user = db.Users.find_one({"userid": userid}, {"_id": 0, "password": 0})  # 비밀번호 제외
    
    if not user:
        return jsonify({'result': 'fail', 'msg' : '사용자가 없습니다.'}), 404
    
    return jsonify({"result": "success", 'user' : user}), 200

# index 화면
@app.route('/get_index', methods=['GET'])
def get_user_index():
    if 'userid' not in session:  # 로그인 확인
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401
    
    return jsonify({"result": "success"}), 200

# 회원 탈퇴
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'userid' not in session:  # 로그인 여부 확인
        return jsonify({"msg": "로그인이 필요합니다."}), 401
    
    userid = session['userid']
    password = request.json.get("password")  # 프론트에서 입력한 비밀번호 받기
    
    # 사용자 정보 조회
    user = db.Users.find_one({"userid": userid})
    if not user:
        return jsonify({'result': 'fail', "msg": "사용자 정보를 찾을 수 없습니다."}), 404

    # 비밀번호 검증
    if not bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        return jsonify({'result': 'fail', "msg": "비밀번호가 틀렸습니다."}), 400

    # 계정 삭제
    db.Users.delete_one({"userid": userid})
    session.clear()  # 세션 삭제 (로그아웃)
    
    return jsonify({'result': 'success', "msg": "탈퇴되었습니다."}), 200

# 게시글과 댓글 삭제
@app.route('/post/<postid>', methods=['DELETE'])
def delete_post(postid):
    if 'userid' not in session:
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401

    # 게시글 찾기
    post = db.Posts.find_one({"postid": postid})
    if not post:
        return jsonify({'result': 'fail', 'msg': '게시글을 찾을 수 없습니다.'}), 400
    
    # 게시글 작성자와 로그인한 사용자가 일치하는지 확인
    userid = session['userid']
    if post.get("author") != userid:
        return jsonify({"result": "fail", "msg": "작성자만 삭제할 수 있습니다."}), 403
    
    # 게시글에 첨부된 파일이 있으면 삭제
    file_path = None
    if post.get("file"):  
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], os.path.basename(post["file"]))

    # 파일이 존재할 때만 삭제 실행
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
            print(f"파일 삭제됨: {file_path}")  # 로그 확인용
        except Exception as e:
            print(f"파일 삭제 중 오류 발생: {e}")  # 예외 처리 추가

    # 게시글 삭제
    db.Posts.delete_one({"postid": postid})

    # 해당 게시글의 모든 댓글 삭제
    db.Comments.delete_many({"postid": postid})

    return jsonify({'result': 'success', 'msg': '게시글과 댓글이 삭제되었습니다.'}), 200

# 게시글 수정
@app.route('/post/<postid>', methods=['PUT'])
def update_post(postid):
    if 'userid' not in session:
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401
    
    post = db.Posts.find_one({"postid": postid}, {"_id": 0})  # postid로 게시글 조회

    if not post:
        return jsonify({"result": "fail", "msg": "해당 게시글을 찾을 수 없습니다."}), 400

    # 게시글 작성자와 로그인한 사용자가 일치하는지 확인
    userid = session['userid']
    if post.get("author") != userid:
        return jsonify({"result": "fail", "msg": "작성자만 수정할 수 있습니다."}), 403

    # 요청 데이터 받기
    title = request.form.get("title")
    content = request.form.get("content")
    file = request.files.get("file")
    file_deleted = request.form.get("fileDeleted") == "true"  # 파일 삭제 여부 확인

    update_data = {
        "title": title,
        "content": content,
        "updatedat": datetime.now()
    }

    # 기존 파일 삭제 로직 추가 (삭제 요청이 있거나 새 파일이 업로드된 경우)
    if file_deleted or file: # file: 사용자가 새로운 파일을 업로드했는지 확인하는 변수.
        if post.get("file"):  # 현재 게시글에 기존 파일이 있는지 확인하는 조건.
            old_file_path = os.path.join(app.config["UPLOAD_FOLDER"], os.path.basename(post["file"]))
            try:
                if os.path.exists(old_file_path):  
                    os.remove(old_file_path)  
                    print(f"기존 파일 삭제됨: {old_file_path}")  
            except Exception as e:
                print(f"기존 파일 삭제 중 오류 발생: {e}")  

        # DB에서도 기존 파일 삭제
        update_data["file"] = None
        update_data["isimage"] = False

    # 파일 업로드 처리
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        # 파일 이름이 중복되면 처리
        while os.path.exists(file_path):
            name, extension = os.path.splitext(filename)
            filename = f"{name}_new{extension}"
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        file.save(file_path)
        update_data["file"] = f"/static/uploads/{filename}"
        update_data["isimage"] = filename.rsplit(".", 1)[-1].lower() in {"png", "jpg", "jpeg", "gif", "webp"}

    db.Posts.update_one({"postid": postid}, {"$set": update_data})

    return jsonify({'result': 'success', 'msg': '게시글이 수정되었습니다.'}), 200

# 회원정보 수정
@app.route('/edit_mypage', methods=['GET'])
def editProfile():
    if 'userid' not in session:  # 로그인 확인
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401

    userid = session['userid']
    # data: { userid: userid, password: password, name: name, email: email } 형식으로 데이터 불러옴
    user = db.Users.find_one({"userid": userid}, {"_id": 0, "password" : 0})
    
    # 응답 데이터 
    return jsonify({
        "result": "success",
        "user": user
    }), 200

# 비밀번호 검증
@app.route('/confirm_pw', methods=['GET'])
def confirm_password():
    if 'userid' not in session:
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401

    userid = session['userid']
    input_password = request.args.get("password")

    print(input_password)

    # DB에서 유저 정보 조회 (비밀번호 포함)
    user = db.Users.find_one({"userid": userid}, {"_id": 0})

    if not user or "password" not in user:
        return jsonify({'result': 'fail', 'msg': '유저 정보를 찾을 수 없습니다.'}), 404

    hashed_password = user["password"]  # DB에서 가져온 해싱된 비밀번호

    # 비밀번호 검증
    if bcrypt.checkpw(input_password.encode('utf-8'), hashed_password):
        return jsonify({'result': 'success', 'msg': '비밀번호 확인되었습니다.'}), 200
    else:
        return jsonify({'result': 'fail', 'msg': '비밀번호가 일치하지 않습니다.'}), 400
    
# 비번 수정
@app.route('/edit_password', methods=['PUT'])
def editPassword():
    if 'userid' not in session:  # 로그인 확인
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401
    
    input_password = request.form.get("password")

    userid = session['userid']
    user = db.Users.find_one({"userid": userid}, {"_id": 0})

    if not user:
        return jsonify({'result': 'fail', 'msg': '유저 정보를 찾을 수 없습니다.'}), 404

    # 비밀번호 해싱 (bcrypt 사용)
    hashed_pw = bcrypt.hashpw(input_password.encode('utf-8'), bcrypt.gensalt())
    
    # 비밀번호 업데이트 (올바른 `update_one` 문법 사용)
    db.Users.update_one({"userid": userid}, {"$set": {"password": hashed_pw}})
    return jsonify({"result": "success", "msg": "비밀번호가 바뀌었습니다."}), 200

# 내 게시글 조회
@app.route('/myposts', methods=['GET'])
def get_my_posts():
    if 'userid' not in session:  # 로그인 확인
        return jsonify({'result': 'fail', 'msg': '로그인이 필요합니다.'}), 401

    userid = session['userid']  # 세션에서 로그인한 사용자 ID 가져오기
    user_posts = list(db.Posts.find({"author": userid}, {'_id': 0}))  # 해당 사용자의 게시글만 조회

    return jsonify({"result": "success", "posts": user_posts}), 200

if __name__ == '__main__':
    app.run('0.0.0.0',port=5000, debug=True)

