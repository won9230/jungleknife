from flask import Flask, render_template, jsonify, request, redirect, url_for
#from apscheduler.schedulers.background import BackgroundScheduler
import bcrypt
from datetime import datetime
from flask_jwt_extended import *
from jwt.exceptions import ExpiredSignatureError

from Config import *

from bson.objectid import ObjectId
from pymongo import MongoClient
client = MongoClient(MONGODB, 27017)
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
    jti = "none"
    jwt_token = request.cookies.get('access_token')
    if jwt_token is None:
        # 일반적인 로그인
        return render_template('login.html'), 200
    
    try:
        jti = decode_token(jwt_token)['jti']
    except ExpiredSignatureError:
        # 쿠키 시간 만료의 경우, 로그인 페이지로
        print("쿠키 만료")
    
    logoutCheck = jti in jwt_blocklist
    if jti == "none" or logoutCheck:
        # 쿠키를 발급받았지만 로그아웃 후 다시 로그인할 때
        return render_template('login.html'), 200
    
    # 쿠키가 유효하여 로그인을 유지한 상태로 main 페이지로 리다이렉션
    return redirect(LOCALHOST + '/main'), 201


## 메인페이지로 이동
@app.route("/main", methods=['GET'])
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
    ################## 메인페이지에 등록 카드 생성 및 갱신 ################
    _all_register = db.register.find().sort('time_finish', 1)
    all_register = list(_all_register)

    return render_template('main.html', user_id=user_id, all_register=all_register)


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


## 물품등록
@app.route('/main',methods=['POST'])
def rental_Registration():
    jwt_token = request.cookies.get('access_token')
    if jwt_token is None:
        return redirect(LOCALHOST+'/'), 400
    
    try:
        user_id = decode_token(jwt_token).get(IDENTITY, None)
    except ExpiredSignatureError:
        # 쿠키 시간 만료의 경우, 로그인 페이지로
        return redirect(LOCALHOST+'/'), 400
    
    input_data = request.form
    product = input_data['product_give']
    time_start = input_data['time_start_give']
    time_finish = input_data['time_finish_give']
    purpose_Rental = input_data['purpose_Rental_give']
    
    rent_user = db.users.find_one({'id': user_id})['name']
    
    db.register.insert_one({'product' : product,'rent_user':rent_user, 'time_start' : time_start,'time_finish' : time_finish,'purpose_Rental' :purpose_Rental, 'reserve_time': '', 'reserve_place': '', 'reserve_user': '', 'product_status': '구하는 중'})
    return jsonify({'result' : 'success', 'msg': '물품 등록 성공'})


## 빌려주기 예약
@app.route("/reservation", methods=['POST'])
def make_reservation():
    jwt_token = request.cookies.get('access_token')
    if jwt_token is None:
        return redirect(LOCALHOST+'/'), 400
    
    try:
        user_id = decode_token(jwt_token).get(IDENTITY, None)
    except ExpiredSignatureError:
        # 쿠키 시간 만료의 경우, 로그인 페이지로
        return redirect(LOCALHOST+'/'), 400
    
    input_data = request.form
    transaction_id = input_data['transaction_id']
    reserve_place = input_data['reserve_place']
    reserve_date = input_data['reserve_date']
    reserve_hour = input_data['reserve_hour']
    
    reserve_user = db.users.find_one({'id': user_id})['name']
    
    time_start = db.register.find_one({'_id': ObjectId(transaction_id)})['time_start']
    time_finish = db.register.find_one({'_id': ObjectId(transaction_id)})['time_finish']
    
    print(time_start +' '+time_finish)
    print(''.join(time_finish.split('-'))[:8])
    if int(''.join(time_finish.split('-'))[:8]) < int(''.join(reserve_date.split('-'))):
        return jsonify({'result' : 'error', 'msg': '종료 날짜가 더 큽니다.'})
    if int(''.join(time_finish.split('-'))[:8]) == int(''.join(reserve_date.split('-'))) and int(''.join(time_finish.split('-'))[8:]) < int(reserve_hour):
        return jsonify({'result' : 'error', 'msg': '종료 시간이 더 큽니다.'})
    else:
        db.register.update_one({'_id': ObjectId(transaction_id)}, {'$set': {
                                                                    'reserve_user': reserve_user,
                                                                    'reserve_place': reserve_place,
                                                                    'reserve_time': reserve_date+reserve_hour,
                                                                    'product_status': '예약 중'
                                                                }
                                                        })      
        return jsonify({'result' : 'success', 'msg': '예약 성공'})
    

##마이페이지 정렬
@app.route("/mypage")
def show_mypage():
    jwt_token = request.cookies.get('access_token')
    if jwt_token is None:
        return redirect(LOCALHOST+'/'), 400
    
    try:
        user_id = decode_token(jwt_token).get(IDENTITY, None)
    except ExpiredSignatureError:
        # 쿠키 시간 만료의 경우, 로그인 페이지로
        return redirect(LOCALHOST+'/'), 400
    
    user = db.users.find_one({'id': user_id})['name']
    _rent_register = db.register.find({'rent_user' : user})
    _reserve_register = db.register.find({'reserve_user' : user})
    rent_register = list(_rent_register)
    reserve_register = list(_reserve_register)
    return render_template("mypage.html",user_id=user_id, rent_register = rent_register , reserve_register = reserve_register)


@app.route('/cancle', methods=['POST'])
def cancle_reservation():
    jwt_token = request.cookies.get('access_token')
    if jwt_token is None:
        return redirect(LOCALHOST+'/'), 400
    
    try:
        user_id = decode_token(jwt_token).get(IDENTITY, None)
    except ExpiredSignatureError:
        # 쿠키 시간 만료의 경우, 로그인 페이지로
        return redirect(LOCALHOST+'/'), 400
    
    input_data = request.form
    transaction_id = input_data['transaction_id']
    
    db.register.update_one({'_id': ObjectId(transaction_id)}, {'$set': {
                                                                'reserve_user': '',
                                                                'reserve_place': '',
                                                                'reserve_time': '',
                                                                'product_status': '구하는 중'
                                                            }
                                                    })
    print(db.register.find_one({'_id': ObjectId(transaction_id)}))
    return jsonify({'result' : 'success', 'msg': '예약 취소 성공'})

## 반납
@app.route('/return', methods=['POST'])
def return_product():
    jwt_token = request.cookies.get('access_token')
    if jwt_token is None:
        return redirect(LOCALHOST+'/'), 400
    
    try:
        user_id = decode_token(jwt_token).get(IDENTITY, None)
    except ExpiredSignatureError:
        # 쿠키 시간 만료의 경우, 로그인 페이지로
        return redirect(LOCALHOST+'/'), 400
    
    input_data = request.form
    transaction_id = input_data['transaction_id']
    
    if(db.register.find_one({'_id': ObjectId(transaction_id)})['product_status'] == '대여 중'):
        db.register.delete_one({'_id': ObjectId(transaction_id)})
        return jsonify({'result' : 'success', 'msg': '반납 완료'})
    else:
        return jsonify({'result' : 'success', 'msg': '아직 물건을 받지 않았습니다.'})
   

## 대여
@app.route('/rental', methods=['POST'])
def rental_product():
    jwt_token = request.cookies.get('access_token')
    if jwt_token is None:
        return redirect(LOCALHOST+'/'), 400
    
    try:
        user_id = decode_token(jwt_token).get(IDENTITY, None)
    except ExpiredSignatureError:
        # 쿠키 시간 만료의 경우, 로그인 페이지로
        return redirect(LOCALHOST+'/'), 400
    
    input_data = request.form
    transaction_id = input_data['transaction_id']
    
    print()
    if(db.register.find_one({'_id': ObjectId(transaction_id)})['product_status'] == '대여 중'):
        return jsonify({'result' : 'success', 'msg': '이미 대여를 완료했습니다.'})
    else: 
        db.register.update_one({'_id': ObjectId(transaction_id)},{'$set':{'product_status':'대여 중'}})
        return jsonify({'result' : 'success', 'msg': '대여 완료'})

def delete():
    print("삭제 중")
    registers = list(db.register.find())
    for reg in registers:
        startTime = reg['time_start']
        startDate = datetime.strptime(startTime[:10], "%Y-%m-%d").date()
        
        startHour = int(startTime[9:])
        

        if startDate < datetime.now().date():
            db.register.delete_many({'time_start': startTime})
        elif startDate == datetime.now().date():
            if startHour <= datetime.now().hour:
                db.register.delete_many({'time_start': startTime})
                
        
        
# schdule = BackgroundScheduler(daemon =True, timezone ='Asia/Seoul')
# schdule.add_job(delete, 'interval', hours=1)
# schdule.start()

if __name__ == '__main__':  
   app.run('0.0.0.0', port=PORT, debug=True)