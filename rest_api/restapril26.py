from flask import Flask
from flask_restful import Api, Resource

app = Flask(__name__)
api = Api(app)


class HelloWorld(Resource):
    def get(self):
        return {'HelloWorld':1}
    
api.add_resource(HelloWorld, '/lights')

if __name__ == '__main__':
    app.run(debug=True, host='10.1.88.3')
















