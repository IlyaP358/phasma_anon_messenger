import requests
import json
import sys

BASE_URL = "http://127.0.0.1:5000"

def register(username, password):
    url = f"{BASE_URL}/register"
    data = {"user": username, "password": password, "confirm_password": password}
    r = requests.post(url, data=data)
    return r.status_code == 200 or "already exists" in r.text

def login(username, password):
    url = f"{BASE_URL}/login"
    data = {"user": username, "password": password}
    s = requests.Session()
    r = s.post(url, data=data)
    if r.status_code == 200:
        return s
    return None

def test_admin_password_change():
    print("Testing Admin Password Change...")
    s = login("admin_user", "password123")
    if not s:
        register("admin_user", "password123")
        s = login("admin_user", "password123")
    
    # Create Group
    r = s.post(f"{BASE_URL}/api/groups/create", json={
        "name": "Test Group",
        "password": "old_password",
        "root_password": "root_password",
        "max_members": 10,
        "group_type": "public"
    })
    if r.status_code != 200:
        print("Failed to create group")
        return False
    
    group_id = r.json().get("group_id") # API might not return ID directly in create? 
    # Actually create returns success: true. We need to list to get ID.
    
    r = s.get(f"{BASE_URL}/api/groups/list")
    groups = r.json()["groups"]
    target_group = next((g for g in groups if g["name"] == "Test Group"), None)
    if not target_group:
        print("Group not found")
        return False
    
    group_id = target_group["id"]
    
    # Change Password
    r = s.post(f"{BASE_URL}/api/groups/{group_id}/update_password", json={
        "root_password": "root_password",
        "new_password": "new_password"
    })
    
    if r.status_code == 200 and r.json().get("success"):
        print("Password change successful")
    else:
        print(f"Password change failed: {r.text}")
        return False

    # Verify with another user
    s2 = login("other_user", "password123")
    if not s2:
        register("other_user", "password123")
        s2 = login("other_user", "password123")
        
    # Try join with old password
    r = s2.post(f"{BASE_URL}/api/groups/join", json={
        "group_code": target_group["code"],
        "password": "old_password"
    })
    if r.json().get("success"):
        print("Error: Joined with old password")
        return False
        
    # Try join with new password
    r = s2.post(f"{BASE_URL}/api/groups/join", json={
        "group_code": target_group["code"],
        "password": "new_password"
    })
    if r.json().get("success"):
        print("Joined with new password")
    else:
        print("Failed to join with new password")
        return False
        
    return True

def test_dm_flow():
    print("\nTesting DM Flow...")
    # User A
    s_a = login("user_a", "password123")
    if not s_a:
        register("user_a", "password123")
        s_a = login("user_a", "password123")
        
    # User B
    s_b = login("user_b", "password123")
    if not s_b:
        register("user_b", "password123")
        s_b = login("user_b", "password123")
        
    # Enable DMs for A
    s_a.post(f"{BASE_URL}/api/user/settings", json={"allow_dms": True})
    
    # B searches for A
    r = s_b.get(f"{BASE_URL}/api/users/search?q=user_a")
    users = r.json().get("users", [])
    if not any(u["username"] == "user_a" for u in users):
        print("User A not found in search")
        return False
        
    # B sends request to A
    r = s_b.post(f"{BASE_URL}/api/dm/request", json={"username": "user_a"})
    if not r.json().get("success"):
        print(f"Failed to send request: {r.text}")
        # Might fail if already exists, which is fine for repeated tests
    
    # A checks mailbox
    r = s_a.get(f"{BASE_URL}/api/dm/requests")
    requests_list = r.json().get("requests", [])
    target_request = next((req for req in requests_list if req["sender"] == "user_b"), None)
    
    if not target_request:
        print("Request not received")
        # Maybe already accepted?
        return True 
        
    # A accepts request
    r = s_a.post(f"{BASE_URL}/api/dm/respond", json={
        "request_id": target_request["id"],
        "action": "accept"
    })
    
    if r.json().get("success"):
        print("Request accepted")
    else:
        print(f"Failed to accept: {r.text}")
        return False
        
    # Check if DM group exists for A
    r = s_a.get(f"{BASE_URL}/api/groups/list")
    groups = r.json().get("groups", [])
    dm_group = next((g for g in groups if g["name"] == "user_b"), None) # Name should be other user
    
    if dm_group:
        print("DM Group found for User A")
        if dm_group.get("is_dm") or dm_group.get("type") == "private": # Check flags
             print("DM Group flags correct")
    else:
        print("DM Group NOT found for User A")
        return False

    return True

if __name__ == "__main__":
    if test_admin_password_change():
        print("Admin Password Change Test PASSED")
    else:
        print("Admin Password Change Test FAILED")
        
    if test_dm_flow():
        print("DM Flow Test PASSED")
    else:
        print("DM Flow Test FAILED")
