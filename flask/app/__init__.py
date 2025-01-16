import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from werkzeug.debug import DebuggedApplication
from flask_socketio import SocketIO
# from flask_login import LoginManager


app = Flask(__name__, static_folder='static')
app.url_map.strict_slashes = False


app.jinja_options = app.jinja_options.copy()
app.jinja_options.update({
    'trim_blocks': True,
    'lstrip_blocks': True
})


app.config['DEBUG'] = True
app.config['SECRET_KEY'] = \
    'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
app.config['JSON_AS_ASCII'] = False


app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite://")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# if app.debug:
#     app.wsgi_app = DebuggedApplication(app.wsgi_app, evalex=True)
# Creating an SQLAlchemy instance
db = SQLAlchemy(app)
socketio = SocketIO(app)
# login_manager = LoginManager()
# login_manager.login_view = 'login'
# login_manager.init_app(app)

from app import views  # noqa