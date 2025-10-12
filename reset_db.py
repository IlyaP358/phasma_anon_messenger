from phasma import app, db, User, Message
from sqlalchemy import inspect

app.app_context().push()

option = input("1 = delete all datas 2 = delete all messages 3 = delete all users ")

# ---DELETE ALL ---
if option == "1":
    inspector = inspect(db.engine)

    if inspector.has_table(Message.__tablename__):
        Message.__table__.drop(db.engine)
        print("[OK] Table 'message' deleted.")

    if inspector.has_table(User.__tablename__):
        User.__table__.drop(db.engine)
        print("[OK] Table 'user' deleted.")

        db.create_all()
        print("[OK] Tables recreated (if needed).")


# --- DELETE MESSAGES --- 
elif option == "2":
    inspector = inspect(db.engine)

    if inspector.has_table(Message.__tablename__):
        Message.__table__.drop(db.engine)
        print("[OK] Table 'message' deleted.")

        db.create_all()
        print("[OK] Tables recreated (if needed).")

# --- DELETE USERS ---        
elif option == "3":
    inspector = inspect(db.engine)

    if inspector.has_table(User.__tablename__):
        User.__table__.drop(db.engine)
        print("[OK] Table 'user' deleted.")

    db.create_all()
    print("[OK] Tables recreated (if needed).")
else:
    print("ERROR")
