from flask import Flask, render_template, jsonify, request, redirect
import jwt
import bcrypt
from flask_jwt_extended import *
from flask_jwt_extended.config import config
from jwt.exceptions import ExpiredSignatureError

from pymongo import MongoClient
client = MongoClient('localhost', 27017)
db = client.jungleknife

SECRET_KEY = 'kraftonjungle'

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = SECRET_KEY
jwt = JWTManager(app)

@app.route('/')
def home():
   return render_template("login.html")

users = [['물품1','이름1','사용기간1','사용목적1'],['물품2','이름2','사용기간2','사용목적2']]



## 메인페이지로 이동
@app.route("/main", methods=['GET'])
def show_main():
    jwtToken = request.cookies.get('mytoken')
    
    if jwtToken is None:
        return render_template('login.html')
    
    try:
        jti = decode_token(jwtToken)['jti']
        user_id = decode_token(jwtToken).get(config.identity_claim_key, None)
    except ExpiredSignatureError:
        return render_template('login.html')
    
    #로그아웃된 token의 경우 로그인 페이지로 redirect
    logoutCheck = jti in jwt_blocklist
    if logoutCheck:
        return render_template('login.html')
    
    return render_template('main.html', user_id=user_id)

## 회원가입 페이지로 이동
@app.route("/join")
def show_join():
    return render_template("join.html")


## API
## 로그인 api
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
        access_token = create_access_token(identity=user_id)
        return jsonify({'result': 'success', 'access_token': access_token}), 200
    # 아이디, 비밀번호가 일치하지 않는 경우
    print('실패')
    return jsonify({'result': 'fail', 'msg': '비밀번호가 틀렸습니다.'})


# blocklist 생성. 중복 방지 위해 set 자료형 사용
jwt_blocklist = set()

# blocklist 기능 사용을 위한 세팅
@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload) :
	jti = jwt_payload['jti']
	return jti in jwt_blocklist

# 로그아웃 api
@app.route('/logout', methods=['GET'])
@jwt_required()
def user_logout() :
    jti = get_jwt()['jti'] 
    jwt_blocklist.add(jti) # 로그인 user의 jti를 blocklist에 등록
    

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
   app.run('0.0.0.0', port=5000, debug=True)