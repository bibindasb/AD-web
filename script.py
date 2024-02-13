from flask import Flask, render_template, request
from ldap3 import Server, Connection, SUBTREE, ALL

app = Flask(__name__)

# Replace these values with your LDAP server and OU information
ldap_server = "your_ldap_server"
base_dn = "OU=Users,DC=domain,DC=com"
group_dn = "CN=YourGroup,OU=Groups,DC=domain,DC=com"  # Specify the DN of the group you want to check

def authenticate(username, password):
    try:
        server = Server(ldap_server, get_info=ALL)
        conn = Connection(server, user=f"{username}@domain.com", password=password, auto_bind=True)

        # Check group membership
        if conn.search(group_dn, f"(member={conn.user_dn})", SUBTREE):
            print(f"User {username} is a member of the group.")
        else:
            print(f"User {username} is not a member of the group.")

        conn.unbind()
        return True
    except Exception as e:
        print(f"Authentication error: {e}")
        return False

def reset_ad_user_password(username, new_password):
    try:
        if len(new_password) < 8:
            return False, "Password must be at least 8 characters"
        server = Server(ldap_server)
        conn = Connection(server, user="admin_username", password="admin_password", auto_bind=True)

        search_filter = f"(sAMAccountName={username})"
        conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=["distinguishedName"])

        if conn.entries:
            user_dn = conn.entries[0].entry_dn
            conn.extend.microsoft.modify_password(user_dn, new_password)
            return True, f"Password reset successfully for user: {username}"
        else:
            return False, f"User not found: {username}"
    except Exception as e:
        return False, f"Error: {e}"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/reset_password", methods=["POST"])
def reset_password():
    username = request.form.get("username")
    new_password = request.form.get("new_password")

    if not authenticate(username, password):
        return render_template("result.html", success=False, message="Authentication failed")

    success, message = reset_ad_user_password(username, new_password)
    return render_template("result.html", success=success, message=message)

if __name__ == "__main__":
    app.run(debug=True)
