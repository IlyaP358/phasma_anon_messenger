from phasma import app, db, User, Message, File, URLPreview
from sqlalchemy import inspect
import os
import glob

app.app_context().push()

print("=" * 60)
print("DATABASE RESET UTILITY")
print("=" * 60)
print("1 = Delete ALL data (users, messages, files)")
print("2 = Delete messages and files only")
print("3 = Delete users only")
print("4 = Delete files only")
print("=" * 60)

option = input("Select option (1-4): ").strip()
folder = os.path.join(os.path.dirname(__file__), 'uploads')

inspector = inspect(db.engine)

# ===============================================================
# OPTION 1: DELETE ALL DATA
# ===============================================================
if option == "1":
    print("\n[WARNING] This will delete ALL data: users, messages, and files!")
    confirm = input("Type 'yes' to confirm: ").strip().lower()
    
    if confirm != 'yes':
        print("[CANCELLED] Operation cancelled.")
        exit()
    
    # Delete Message table
    if inspector.has_table(Message.__tablename__):
        Message.__table__.drop(db.engine)
        print("[OK] Table 'message' deleted.")
    else:
        print("[INFO] Table 'message' does not exist.")
    
    # Delete User table
    if inspector.has_table(User.__tablename__):
        User.__table__.drop(db.engine)
        print("[OK] Table 'user' deleted.")
    else:
        print("[INFO] Table 'user' does not exist.")
    
    # Delete File table (renamed from Photo)
    if inspector.has_table(File.__tablename__):
        File.__table__.drop(db.engine)
        print("[OK] Table 'file' deleted.")
    else:
        print("[INFO] Table 'file' does not exist.")
    
    # Recreate tables
    db.create_all()
    print("[OK] Tables recreated.")
    
    # Delete all files from uploads folder
    if os.path.exists(folder):
        deleted_count = 0
        for file_path in glob.glob(os.path.join(folder, "*")):
            try:
                os.remove(file_path)
                deleted_count += 1
                print(f"[DELETE] {os.path.basename(file_path)}")
            except Exception as e:
                print(f"[ERROR] Could not delete {file_path}: {e}")
        print(f"[OK] Deleted {deleted_count} files from uploads folder.")
    else:
        print("[INFO] Uploads folder does not exist.")
    
    print("\n[COMPLETE] All data deleted successfully!")

# ===============================================================
# OPTION 2: DELETE MESSAGES AND FILES
# ===============================================================
elif option == "2":
    print("\n[WARNING] This will delete all messages and files!")
    confirm = input("Type 'yes' to confirm: ").strip().lower()
    
    if confirm != 'yes':
        print("[CANCELLED] Operation cancelled.")
        exit()
    
    # Delete Message table
    if inspector.has_table(Message.__tablename__):
        Message.__table__.drop(db.engine)
        print("[OK] Table 'message' deleted.")
    else:
        print("[INFO] Table 'message' does not exist.")
    
    # Delete File table
    if inspector.has_table(File.__tablename__):
        File.__table__.drop(db.engine)
        print("[OK] Table 'file' deleted.")
    else:
        print("[INFO] Table 'file' does not exist.")

    # Delete URLs
    if inspector.has_table(URLPreview.__tablename__):
        URLPreview.__table__.drop(db.engine)
        print("[OK] Table 'file_preview' deleted.")
    else:
        print("[INFO] Table 'file_preview' does not exist.")
    
    # Recreate tables
    db.create_all()
    print("[OK] Tables recreated.")
    
    # Delete all files from uploads folder
    if os.path.exists(folder):
        deleted_count = 0
        for file_path in glob.glob(os.path.join(folder, "*")):
            try:
                os.remove(file_path)
                deleted_count += 1
                print(f"[DELETE] {os.path.basename(file_path)}")
            except Exception as e:
                print(f"[ERROR] Could not delete {file_path}: {e}")
        print(f"[OK] Deleted {deleted_count} files from uploads folder.")
    else:
        print("[INFO] Uploads folder does not exist.")
    
    print("\n[COMPLETE] Messages and files deleted successfully!")

# ===============================================================
# OPTION 3: DELETE USERS ONLY
# ===============================================================
elif option == "3":
    print("\n[WARNING] This will delete all users!")
    confirm = input("Type 'yes' to confirm: ").strip().lower()
    
    if confirm != 'yes':
        print("[CANCELLED] Operation cancelled.")
        exit()
    
    # Delete User table
    if inspector.has_table(User.__tablename__):
        User.__table__.drop(db.engine)
        print("[OK] Table 'user' deleted.")
    else:
        print("[INFO] Table 'user' does not exist.")
    
    # Recreate tables
    db.create_all()
    print("[OK] Tables recreated.")
    
    print("\n[COMPLETE] Users deleted successfully!")

# ===============================================================
# OPTION 4: DELETE FILES ONLY
# ===============================================================
elif option == "4":
    print("\n[WARNING] This will delete all files (photos, videos, audio, documents)!")
    confirm = input("Type 'yes' to confirm: ").strip().lower()
    
    if confirm != 'yes':
        print("[CANCELLED] Operation cancelled.")
        exit()
    
    # Delete File table
    if inspector.has_table(File.__tablename__):
        File.__table__.drop(db.engine)
        print("[OK] Table 'file' deleted.")
    else:
        print("[INFO] Table 'file' does not exist.")
    
    # Recreate tables
    db.create_all()
    print("[OK] Tables recreated.")
    
    # Delete all files from uploads folder
    if os.path.exists(folder):
        deleted_count = 0
        for file_path in glob.glob(os.path.join(folder, "*")):
            try:
                os.remove(file_path)
                deleted_count += 1
                print(f"[DELETE] {os.path.basename(file_path)}")
            except Exception as e:
                print(f"[ERROR] Could not delete {file_path}: {e}")
        print(f"[OK] Deleted {deleted_count} files from uploads folder.")
    else:
        print("[INFO] Uploads folder does not exist.")
    
    print("\n[COMPLETE] Files deleted successfully!")

# ===============================================================
# INVALID OPTION
# ===============================================================
else:
    print("[ERROR] Invalid option! Please select 1, 2, 3, or 4.")
    exit(1)
