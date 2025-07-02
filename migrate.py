from app import app, db
from flask_migrate import Migrate, upgrade, migrate, init, revision

migrate = Migrate(app, db)
