<<<<<<< HEAD
PORT = 5000
LOCALHOST = 'localhost'
LOCALHOST_ADDRESS = 'http://:'+LOCALHOST+str(PORT)
AWS_IP = '13.209.99.72'
AWS_ADDRESS = 'http://'+AWS_IP+str(PORT)
MONGODB = 'mongodb://test:1234@' + AWS_ADDRESS
=======

PORT = 5000
LOCALHOST = 'http://127.0.0.1:'+str(PORT)
>>>>>>> b007dab7ab8a9eb183093f44443c6484366a13bc

SECRET_KEY = 'kraftonjungle'
ACCESS_TIME = 60 * 30
REFRESH_TIME = 60 * 60 * 24 * 30
IDENTITY = 'sub'