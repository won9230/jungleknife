from flask import Flask,render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('main.html',users = users)

users = [['물품1','이름1','사용기간1','사용목적1'],['물품2','이름2','사용기간2','사용목적2']]



@app.route('/main')
def cradReload():
    return render_template('main.html')

if __name__ == '__main__':
    app.run(debug=True)