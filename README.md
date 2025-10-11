# φ Phasma — Anonymous Web Messenger over Tor

**Phasma** is a next-generation anonymous web messenger built for **privacy**, **security**, and **freedom of communication**. All traffic is routed through the [Tor network](https://www.torproject.org/), making messages nearly impossible to trace or intercept.

> ⚠️ This project is in **early development**. Features and UI will evolve rapidly.

---

## 🧱 Key Features (Planned / Partially Implemented)

- 🛡️ **Full Anonymity**: Connections route through Tor, hiding your IP and location.
- 🔐 **Privacy-First**: No logs, no metadata collection, no third-party sharing.
- 🌐 **Browser-Based**: Works with **Firefox**, **Chrome**, **Edge**, and other modern browsers—no installation needed.
- 🗨️ **Secure Chats**: Only you and your recipient can read messages.
- 🧩 **Lightweight**: Minimal dependencies, easy to deploy.

---

## ⚙️ Installation & Local Setup

Follow these steps to set up **Phasma** locally with a PostgreSQL database.

### 1. Clone the Repository
Clone the project and navigate to the directory:
```
git clone https://github.com/IlyaP358/phasma_anon_messenger.git
cd phasma_anon_messenger
```

### 2. Set Up **PostgreSQL**
Install and configure PostgreSQL based on your operating system.

#### **Arch Linux**
- Install PostgreSQL:
  ```
  sudo pacman -S postgresql
  ```
- Initialize the database (if not already done):
  ```
  sudo -iu postgres initdb --locale=$LANG -D /var/lib/postgres/data
  exit
  ```
- Enable and start the PostgreSQL service:
  ```
  sudo systemctl enable postgresql
  sudo systemctl start postgresql
  ```

#### **Ubuntu**
- Install PostgreSQL:
  ```
  sudo apt update
  sudo apt install postgresql postgresql-contrib
  ```
- Verify the service is running (it usually starts automatically):
  ```
  sudo systemctl status postgresql
  ```

### 3. Create **Database** and **User**
- Connect to PostgreSQL:
  ```
  sudo -u postgres psql
  ```
- In the `psql` prompt, create a database (e.g., `phasma`) and user (e.g., `phasma_user`):
  ```
  CREATE DATABASE phasma;
  CREATE USER phasma_user WITH PASSWORD 'your_password';
  GRANT ALL PRIVILEGES ON DATABASE phasma TO phasma_user;
  \q
  ```

### 4. Set Up **Python Environment**
- Install Python 3 and pip:
  - **Arch Linux**:
    ```
    sudo pacman -S python python-pip
    ```
  - **Ubuntu**:
    ```
    sudo apt install python3 python3-pip python3-venv
    ```
- Create and activate a virtual environment:
  ```
  python3 -m venv venv
  source venv/bin/activate
  ```

### 5. Install **Python Dependencies**
- Install required libraries:
  ```
  pip install flask flask_sqlalchemy psycopg2
  ```
- **Optional**: Use `psycopg2-binary` for simpler setup:
  ```
  pip install psycopg2-binary
  ```

### 6. Database Management Tools
- **Terminal-Based**:
  - Use `psql` (included with PostgreSQL).
  - For syntax highlighting, install `pgcli`:
    - **Arch Linux**:
      ```
      sudo pacman -S pgcli
      ```
    - **Ubuntu**:
      ```
      sudo apt install pgcli
      ```
- **GUI-Based** (Optional):
  - Use **VS Code** with **SQLTools** and **PostgreSQL Driver**.
  - Install **DBeaver** or **pgAdmin** for a graphical interface.

### 7. Configure **Flask Application**
- Set the database URI in your Flask app:
  ```python
  SQLALCHEMY_DATABASE_URI = 'postgresql://phoneuser:your_password@localhost/phonebook_db'
  ```
- Create database tables:
  ```python
  from your_app import db
  db.create_all()
  ```
- Run the Flask server:
  ```
  python phasma.py
  ```
- For public access (e.g., on a server), configure the host:
  ```python
  app.run(host="0.0.0.0")
  ```
- **Note**: On Ubuntu servers, ensure port 5000 is open in your firewall.

### 8. Install Project Dependencies
Install dependencies listed in `requirements.txt`:
```
pip install -r requirements.txt
```

### 9. Run the Application
Start the application:
```
python phasma.py
```%  
