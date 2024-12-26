from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mongoengine import MongoEngine

app = Flask(__name__)

# Configurations
app.config['MONGODB_SETTINGS'] = {
    'db': 'jwt_auth',
    'host': 'localhost',
    'port': 27017
}
app.config['JWT_SECRET_KEY'] = 'your_secret_key'

# Initialize extensions
db = MongoEngine(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User model
class User(db.Document):
    username = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)

# Registration route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    if User.objects(username=username).first():
        return jsonify({"msg": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, password=hashed_password)
    user.save()

    return jsonify({"msg": "User registered successfully"}), 201

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    user = User.objects(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token), 200

# Protected route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.objects(id=current_user_id).first()
    return jsonify(logged_in_as=user.username), 200

if __name__ == '__main__':
    app.run(port=5000)