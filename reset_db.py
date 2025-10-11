from phasma import app, db, User, Message

with app.app_context():
    Message.query.delete()
    User.query.delete()
    db.session.commit()
print("[OK] ALL datas deleted.")
