PORT = 5000
LOCALHOST = 'localhost'
LOCALHOST_ADDRESS = 'http://:'+LOCALHOST+str(PORT)
AWS_IP = '13.209.99.72'
AWS_ADDRESS = 'http://'+AWS_IP+str(PORT)
MONGODB = 'mongodb://test:1234@' + AWS_ADDRESS

SECRET_KEY = 'kraftonjungle'
ACCESS_TIME = 60 * 30
REFRESH_TIME = 60 * 60 * 24 * 30
IDENTITY = 'sub'