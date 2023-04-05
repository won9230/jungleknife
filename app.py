from flask import Flask, render_template, jsonify, request, redirect, url_for
import bcrypt
from flask_jwt_extended import *
from datetime import datetime, timedelta
from flask_jwt_extended.config import config
from jwt.exceptions import ExpiredSignatureError

from Config import *

from pymongo import MongoClient
client = MongoClient('localhost', 27017)
db = client.jungleknife

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = ACCESS_TIME
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = REFRESH_TIME

jwt = JWTManager(app)
# blocklist 생성. 중복 방지 위해 set 자료형 사용
jwt_blocklist = set()


######################
######################
######################
@app.route('/')
def home():
    jwt_token = request.cookies.get('access_token')
    if jwt_token is None:
        # 일반적인 로그인
        return render_template('login.html'), 200
    
    jti = decode_token(jwt_token)['jti']
    if jti in jwt_blocklist:
        # 쿠키를 발급받았지만 로그아웃 후 다시 로그인할 때
        return render_template('login.html'), 200
    
    # 쿠키가 유효하여 로그인을 유지한 상태로 main 페이지로 리다이렉션
    return redirect(LOCALHOST + '/main'), 201


## 메인페이지로 이동
@app.route("/main")
def show_main():
    jwt_token = request.cookies.get('access_token')
    if jwt_token is None:
        return redirect(LOCALHOST+'/'), 400
    
    try:
        # token decode 후 로그아웃여부 확인 위해 jti 저장, user 정보 저장
        jti = decode_token(jwt_token)['jti']
        user_id = decode_token(jwt_token).get(IDENTITY, None)
    except ExpiredSignatureError:
        # 쿠키 시간 만료의 경우, 로그인 페이지로
        return redirect(LOCALHOST+'/'), 400
    
    #logout된 token의 경우 login페이지 rediect
    logoutCheck = jti in jwt_blocklist
    if logoutCheck:
        return redirect(LOCALHOST+'/'), 400
    print(user_id)
    return render_template('main.html', user_id=user_id)

@app.route("/main/<user_id>")
def show_mypage(user_id):
    return render_template("mypage.html", user_id)

## 회원가입 페이지로 이동
@app.route("/join")
def show_join():
    return render_template("join.html")


@app.route("/register")
def show_register():
    return render_template("register.html")


@app.route("/rent")
def show_rent():
    return render_template("rent.html")




################################
## API
## 로그인 api
################################
@app.route("/login", methods=['POST'])
def login_proc():
    input_data = request.form
    user_id = input_data['id']
    user_pw = input_data['pw']
    
    # 
    users = list(db.users.find({'id': user_id}))
    
    if len(users) == 0:
        # 아이디 존재하지 않는 경우
        return jsonify({'result': 'fail', 'msg': 'ID가 존재하지 않습니다.'})
    
    if bcrypt.checkpw(user_pw.encode('utf-8'), users[0]['pw']):
        # 아이디, 비밀번호가 일치하는 경우
        user_id = users[0]['id']
        access_token = create_access_token(identity=user_id)
        refresh_token = create_refresh_token(identity=user_id)
        
        return jsonify({'result': 'success', 'user_id': user_id, 'access_token': access_token, 'refresh_token': refresh_token}), 200
    # 아이디, 비밀번호가 일치하지 않는 경우
    print('실패')
    return jsonify({'result': 'fail', 'msg': '비밀번호가 틀렸습니다.'})

# blocklist 기능 사용을 위한 세팅
@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload):
	jti = jwt_payload['jti']
	return jti in jwt_blocklist


# 로그아웃 api
@app.route('/logout', methods=['GET'])
def logout_proc():
    jwt_token = request.cookies.get('access_token')
    
    jti = decode_token(jwt_token)['jti']
    jwt_blocklist.add(jti) # 로그인 user의 jti를 blocklist에 등록
    
    return jsonify({'result': 'success', 'msg': '로그아웃 성공!'})
    

## 회원가입 api
@app.route("/register", methods=['POST'])
def register_user():
    input_data = request.form
    user_id = input_data['id']
    user_pw = input_data['pw']
    user_name = input_data['name']
    
    ## 아이디 중복 확인
    users = list(db.users.find())
    for u in users:
        if u['id'] == user_id:
            return jsonify({'result': 'fail', 'msg': 'ID 중복!'})
    
    ## 비밀번호 암호화
    byted_pw = bcrypt.hashpw(user_pw.encode('utf-8'), bcrypt.gensalt())
    
    ## 데이터베이스 등록
    db.users.insert_one({'id': user_id, 'pw': byted_pw, 'name': user_name})
    return jsonify({'result': 'success', 'msg': 'Join Success!'})


if __name__ == '__main__':  
   app.run('0.0.0.0', port=PORT, debug=True)