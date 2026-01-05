from flask import Flask, render_template, request, jsonify
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPBindError, LDAPException
import hashlib
import base64
import os

app = Flask(__name__)

# LDAP Configuration
LDAP_SERVER = 'ldap://localhost:389'
LDAP_BASE_DN = 'dc=ldap,dc=local'
LDAP_ADMIN_DN = 'cn=admin,dc=ldap,dc=local'
LDAP_ADMIN_PASSWORD = 'xxxx'  # Replace with actual admin password
LDAP_PEOPLE_OU = 'ou=People,dc=ldap,dc=local'

def hash_password(password):
    """Create SSHA hash for LDAP password"""
    salt = os.urandom(4)
    sha = hashlib.sha1(password.encode('utf-8'))
    sha.update(salt)
    digest = sha.digest()
    b64_encoded = base64.b64encode(digest + salt).decode('utf-8')
    return '{SSHA}' + b64_encoded

def check_user_exists(enrollment_id):
    """Check if user exists in LDAP"""
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD, auto_bind=True)
        
        user_dn = f'uid={enrollment_id},{LDAP_PEOPLE_OU}'
        print(f"Searching for user DN: {user_dn}")
        conn.search(user_dn, '(objectClass=*)', attributes=['uid'])
        
        print(f"Search result: {conn.entries}")
        print(f"Number of entries: {len(conn.entries)}")
        conn.unbind()
        return conn.entries is not None and len(conn.entries) > 0
    except Exception as e:
        print(f"Error checking user: {e}")
        return False

def verify_current_password(enrollment_id, current_password):
    """Verify the user's current password by attempting to bind"""
    try:
        user_dn = f'uid={enrollment_id},{LDAP_PEOPLE_OU}'
        server = Server(LDAP_SERVER, get_info=ALL)
        
        print(f"Verifying current password for: {user_dn}")
        # Try to bind with the provided current password
        conn = Connection(server, user_dn, current_password)
        if conn.bind():
            print("Current password verified successfully")
            conn.unbind()
            return True
        else:
            print("Current password verification failed")
            return False
    except LDAPBindError as e:
        print(f"LDAPBindError - invalid current password: {e}")
        return False
    except Exception as e:
        print(f"Exception verifying password: {e}")
        return False

def change_user_password(enrollment_id, new_password):
    """Change password for a user (uses admin connection)"""
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD, auto_bind=True)
        
        user_dn = f'uid={enrollment_id},{LDAP_PEOPLE_OU}'
        hashed_password = hash_password(new_password)
        
        print(f"Changing password for: {user_dn}")
        conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [hashed_password])]})
        
        result = conn.result['result'] == 0
        print(f"Password change result: {result}")
        conn.unbind()
        return result
    except Exception as e:
        print(f"Error changing password: {e}")
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/change-password', methods=['POST'])
def change_password():
    data = request.get_json()
    enrollment_id = data.get('enrollment_id', '').strip()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    print(f"Received password change request for enrollment_id: {enrollment_id}")
    
    # Validate input
    if not enrollment_id or not current_password or not new_password:
        return jsonify({'status': 'error', 'message': 'Please provide enrollment ID, current password, and new password'}), 400
    
    # Check if new password is different from current
    if current_password == new_password:
        return jsonify({'status': 'error', 'message': 'New password must be different from current password'}), 400
    
    # Check if user exists
    if not check_user_exists(enrollment_id):
        print(f"User {enrollment_id} not found")
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    # Verify current password
    if not verify_current_password(enrollment_id, current_password):
        print(f"Current password verification failed for {enrollment_id}")
        return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 401
    
    # Change the password
    if change_user_password(enrollment_id, new_password):
        print(f"Password changed successfully for {enrollment_id}")
        return jsonify({'status': 'success', 'message': 'Password changed successfully'}), 200
    else:
        print(f"Failed to change password for {enrollment_id}")
        return jsonify({'status': 'error', 'message': 'Failed to change password. Please try again'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)