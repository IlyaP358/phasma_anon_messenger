from phasma import app, db, User, Message
from sqlalchemy import inspect
import os
import glob
import os

app.app_context().push()

option = input("1 = delete all datas 2 = delete all messages 3 = delete all users 4 = delete photos")
folder = os.path.join(os.path.dirname(__file__), 'uploads')

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

        for file in glob.glob(os.path.join(folder, "*")):
            print(file) 
            os.remove(file)

# --- DELETE MESSAGES --- 
elif option == "2":
    inspector = inspect(db.engine)

    if inspector.has_table(Message.__tablename__):
        Message.__table__.drop(db.engine)
        print("[OK] Table 'message' deleted.")

        db.create_all()
        print("[OK] Tables recreated (if needed).")

        for file in glob.glob(os.path.join(folder, "*")):
            print("Delete photo file =>",file) 
            os.remove(file)

# --- DELETE USERS ---        
elif option == "3":
    inspector = inspect(db.engine)

    if inspector.has_table(User.__tablename__):
        User.__table__.drop(db.engine)
        print("[OK] Table 'user' deleted.")

    db.create_all()
    print("[OK] Tables recreated (if needed).")

# --- DELETE PHOTOS ---
elif option == "4":
    for file in glob.glob(os.path.join(folder, "*")):
        print(file) 
        os.remove(file)
else:
    print("ERROR")
