import datetime
import uuid

import enum as enum
from flask import Flask, jsonify, g, render_template, session
from flask import request
from flask_httpauth import HTTPBasicAuth
from flask_marshmallow import Marshmallow
from flask_restful import Api, abort
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy.dialects.postgresql import UUID

app = Flask(__name__)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'postgres://jnasxtexwoezbw:40533f0ebf739a9985dee139359225c3f45ec775c433ef8ad663658ccc0247c4@ec2-3-215-118-246.compute-1.amazonaws.com:5432/df40iv88s8qt50'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'S3cretH4sh'
db = SQLAlchemy(app)
ma = Marshmallow(app)
api = Api(app)
auth = HTTPBasicAuth()


class User(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    username = db.Column(db.String(40), unique=True)
    first_name = db.Column(db.String(40))
    last_name = db.Column(db.String(40))
    email = db.Column(db.String(200), unique=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': str(self.id)})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return False
        user = User.query.get(data['id'])
        return user


@auth.error_handler
def auth_error():
    return 'Access Denied', 403


class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "username", "first_name", "last_name", "email")


post_schema = UserSchema()
posts_schema = UserSchema(many=True)


class EnumCategory(enum.Enum):
    Conferencia = 1
    Seminario = 2
    Congreso = 3
    Curso = 4


class Event(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    name = db.Column(db.String(100), unique=True)
    category = db.Column(db.Enum('Conferencia', 'Seminario', 'Congreso', 'Curso', name="CategoryTypes"),
                         default='Conferencia')
    place = db.Column(db.String(40))
    address = db.Column(db.String(200))
    begin_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    is_virtual = db.Column(db.Boolean)
    creation_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey('user.id')
    )


class EventSchema(ma.Schema):
    class Meta:
        model = Event
        fields = ("id", "name", "category", "place", "address", "begin_date", "end_date", "is_virtual", "creation_date"
                  , "user_id")


event_schema = EventSchema()
events_schema = EventSchema(many=True)


@app.route('/api/user/', methods=['POST'])
def post():
    if request.json['username'] is None or request.json['password'] is None:
        abort(400)  # missing arguments
    if User.query.filter_by(username=request.json['username']).first() is not None:
        abort(400)  # existing user
    newClient = User(
        username=request.json['username'],
        first_name=request.json['first_name'],
        last_name=request.json['last_name'],
        email=request.json['email']
    )
    newClient.hash_password(request.json['password'])
    db.session.add(newClient)
    db.session.commit()
    return post_schema.dump(newClient)


@app.route('/api/token', methods=['GET', 'POST'])
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()

    # Put it in the session
    session['api_session_token'] = token
    return jsonify({'token': token.decode('ascii')})


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/listevent', methods=['GET'])
@auth.login_required
def getEvents():
    events = Event.query.filter(Event.user_id == g.user.id).order_by(Event.creation_date.desc()).all()
    result = events_schema.dump(events)
    return jsonify(result.data)


@app.route('/api/createevent', methods=['POST'])
@auth.login_required
def postEvent():
    new_event = Event(
        name=request.json['name'],
        category=request.json['category'],
        place=request.json['place'],
        address=request.json['address'],
        begin_date=request.json['begin_date'],
        end_date=request.json['end_date'],
        is_virtual=request.json['is_virtual'],
        user_id=g.user.id
    )
    db.session.add(new_event)
    db.session.commit()
    return event_schema.dump(new_event)


@app.route('/api/event/<string:id_event>', methods=['GET'])
@auth.login_required
def getEventById(id_event):
    event = Event.query.get_or_404(id_event)
    return event_schema.dump(event)


@app.route('/api/updateevent/<string:id_event>', methods=['PUT'])
@auth.login_required
def put(id_event):
    event = Event.query.get_or_404(id_event)
    if 'name' in request.json:
        event.name = request.json['name']
    if 'category' in request.json:
        event.category = request.json['category']
    if 'place' in request.json:
        event.place = request.json['place']
    if 'address' in request.json:
        event.address = request.json['address']
    if 'begin_date' in request.json:
        event.begin_date = request.json['begin_date']
    if 'end_date' in request.json:
        event.end_date = request.json['end_date']
    if 'is_virtual' in request.json:
        event.is_virtual = request.json['is_virtual']
    if 'user_id' in request.json:
        event.user_id = request.json['user_id']

    db.session.commit()
    return event_schema.dump(event)


@app.route('/api/deleteevent/<string:id_event>', methods=['DELETE'])
@auth.login_required
def delete(id_event):
    event = Event.query.get_or_404(id_event)
    db.session.delete(event)
    db.session.commit()
    return '', 204


@app.route('/')
def inicio():
    return render_template("login.html")


@app.route('/register')
def register():
    return render_template("register.html")


@app.route('/event')
def event():
    return render_template("event.html")


@app.route("/event/detail/<id>", methods=['PUT', 'GET'])
@app.route("/event/detail/", methods=['POST', 'GET'])
def editEvent(id=None):
    return render_template("createevent.html", id=id)


if __name__ == '__main__':
    app.run(debug=True)
