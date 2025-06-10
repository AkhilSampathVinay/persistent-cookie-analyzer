import os
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from fpdf import FPDF
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import shutil

# Get the current Windows username automatically
username = os.getlogin()

# Chrome profile path based on the username
chrome_profile_base_path = os.path.expanduser(f"C:\\Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data")

# Function to get all profile names in Chrome's User Data directory
def get_chrome_profiles():
    profiles = []
    if os.path.exists(chrome_profile_base_path):
        # List directories in the User Data folder
        for folder_name in os.listdir(chrome_profile_base_path):
            folder_path = os.path.join(chrome_profile_base_path, folder_name)
            if os.path.isdir(folder_path) and (folder_name.startswith("Profile") or folder_name == "Default"):
                profiles.append(folder_name)
    return profiles

# Part 1: Cookie Extractors
def get_chrome_cookies(profile="Default"):
    cookies_path = os.path.join(chrome_profile_base_path, profile, "Network", "Cookies")
    if not os.path.exists(cookies_path):
        print(f"Cookies database for {profile} not found!")
        return pd.DataFrame()
    
    try:
        conn = sqlite3.connect(cookies_path)
        query = """
        SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly, samesite
        FROM cookies
        """
        cookies = pd.read_sql_query(query, conn)
        conn.close()
        return cookies
    except Exception as e:
        print(f"Error parsing Chrome cookies: {e}")
        return pd.DataFrame()

def delete_cookies(cookie_list, profile="Default"):
    cookies_path = os.path.join(chrome_profile_base_path, profile, "Network", "Cookies")
    if not os.path.exists(cookies_path):
        print(f"Cookies database for {profile} not found!")
        return False

    try:
        temp_path = cookies_path + "_temp"
        shutil.copyfile(cookies_path, temp_path)  # Create a temporary copy
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()

        # Delete each cookie in the list
        for domain, name in cookie_list:
            cursor.execute(
                "DELETE FROM cookies WHERE host_key = ? AND name = ?",
                (domain, name)
            )

        conn.commit()
        conn.close()
        shutil.move(temp_path, cookies_path)  # Replace the original database
        return True
    except Exception as e:
        print(f"Error deleting cookies: {e}")
        return False

# Part 2: Risk Analyzer
def analyze_cookie(cookie):
    try:
        expiry = datetime(1601, 1, 1) + timedelta(microseconds=cookie.get("expires_utc", 0))
    except Exception:
        expiry = datetime.now()
    active = "Active" if expiry > datetime.now() else "Not Active"
    persistent = expiry > datetime.now() + timedelta(days=7)
    secure = bool(cookie.get("is_secure", False))
    httponly = bool(cookie.get("is_httponly", False))
    samesite = cookie.get("samesite", "None")
    risk_score = 0
    risks = []

    if not secure:
        risk_score += 1
        risks.append("Missing Secure flag.")
    if not httponly:
        risk_score += 1
        risks.append("Missing HttpOnly flag.")
    if samesite not in ["Lax", "Strict"]:
        risk_score += 1
        risks.append("Invalid SameSite flag.")
    
    return {
        "Domain": cookie.get("host_key", cookie.get("host", "Unknown")),
        "Name": cookie.get("name"),
        "Expiry": expiry.strftime("%Y-%m-%d %H:%M:%S"),
        "Active": active,
        "Persistent": persistent,
        "Secure": secure,
        "HttpOnly": httponly,
        "SameSite": samesite,
        "Risk Score": risk_score,
        "Risks": ", ".join(risks)
    }

# Part 3: Graphical User Interface
def toggle_checkbox(item_id):
    current_value = tree.item(item_id, "values")[0]
    new_value = "[X]" if current_value == "[ ]" else "[ ]"
    tree.set(item_id, column="Checkbox", value=new_value)

def display_cookies(cookies):
    for row in tree.get_children():
        tree.delete(row)
    for cookie in cookies:
        tree.insert("", "end", values=(
            "[ ]", cookie["Domain"], cookie["Name"], cookie["Expiry"], cookie["Active"], cookie["Risk Score"], cookie["Risks"]
        ))

def extract_and_display_cookies(profile="Default", filter_status="All", min_risk_score="All"):
    global analyzed_cookies
    cookies = get_chrome_cookies(profile)
    if cookies.empty:
        messagebox.showwarning("No Cookies", f"No cookies found for the profile: {profile}.")
        return

    analyzed_cookies = [analyze_cookie(cookie) for cookie in cookies.to_dict("records")]

    # Apply status filter
    filtered_cookies = analyzed_cookies
    if filter_status != "All":
        filtered_cookies = [cookie for cookie in filtered_cookies if cookie["Active"] == filter_status]

    # Apply risk score filter
    if min_risk_score != "All":
        min_risk_score = int(min_risk_score)
        filtered_cookies = [cookie for cookie in filtered_cookies if cookie["Risk Score"] == min_risk_score]

    display_cookies(filtered_cookies)
    result_text.set(f"Displayed {len(filtered_cookies)} cookies successfully!")

def delete_selected_cookies(profile="Default"):
    selected_items = [item for item in tree.get_children() if tree.item(item, "values")[0] == "[X]"]
    if not selected_items:
        messagebox.showwarning("No Selection", "Please select cookies to delete.")
        return

    cookies_to_delete = [
        (tree.item(item, "values")[1], tree.item(item, "values")[2])
        for item in selected_items
    ]

    if delete_cookies(cookies_to_delete, profile):
        messagebox.showinfo("Success", f"Deleted {len(cookies_to_delete)} cookies successfully.")
        extract_and_display_cookies(profile=profile_combobox.get(), filter_status=filter_combobox.get(), min_risk_score=risk_combobox.get())  # Reapply filters after deletion
    else:
        messagebox.showerror("Error", "Failed to delete some or all cookies.")

def on_tree_click(event):
    item_id = tree.identify_row(event.y)
    if item_id and tree.identify_column(event.x) == "#1":  # Check if the checkbox column was clicked
        toggle_checkbox(item_id)

def generate_report():
    # Prompt user for report type
    report_type = messagebox.askquestion(
        "Report Type",
        "Do you want to generate a report for all cookies?\n"
        "Click 'Yes' for all cookies, 'No' for only displayed cookies.",
        icon="question"
    )

    if report_type == "All":
        # Generate a report for all cookies
        cookies_to_report = analyzed_cookies
    else:
        # Generate a report for displayed (filtered) cookies
        cookies_to_report = [
            {
                "Domain": tree.item(item, "values")[1],
                "Name": tree.item(item, "values")[2],
                "Expiry": tree.item(item, "values")[3],
                "Active": tree.item(item, "values")[4],
                "Risk Score": tree.item(item, "values")[5],
                "Risks": tree.item(item, "values")[6],
            }
            for item in tree.get_children()
        ]

    if not cookies_to_report:
        messagebox.showwarning("No Data", "No cookies to generate a report. Please apply filters or extract cookies.")
        return

    # Ask for save location
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pdf", 
        filetypes=[("PDF files", "*.pdf")],
        title="Save Report"
    )
    if not file_path:
        return

    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        pdf.cell(200, 10, txt="Persistent Cookie Analyzer Report", ln=True, align="C")
        pdf.ln(10)

        for cookie in cookies_to_report:
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(
                0, 
                10, 
                txt=(
                    f"Domain: {cookie['Domain']}\n"
                    f"Name: {cookie['Name']}\n"
                    f"Expiry: {cookie['Expiry']}\n"
                    f"Active: {cookie['Active']}\n"
                    f"Risk Score: {cookie['Risk Score']}\n"
                    f"Risks: {cookie['Risks']}\n"
                    "-----------------------------"
                )
            )
            pdf.ln(5)

        pdf.output(file_path)
        messagebox.showinfo("Success", "Report generated successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate report: {e}")

def select_all_cookies():
    for item in tree.get_children():
        tree.set(item, column="Checkbox", value="[X]")

def deselect_all_cookies():
    for item in tree.get_children():
        tree.set(item, column="Checkbox", value="[ ]")
def on_tree_double_click(event):
    item_id = tree.identify_row(event.y)
    if item_id:
        # Extract cookie details from the row
        domain = tree.item(item_id, "values")[1]
        name = tree.item(item_id, "values")[2]
        expiry = tree.item(item_id, "values")[3]
        active = tree.item(item_id, "values")[4]
        risk_score = tree.item(item_id, "values")[5]
        risks = tree.item(item_id, "values")[6]
        
        # Find the corresponding cookie from the analyzed cookies list
        cookie = next((cookie for cookie in analyzed_cookies if cookie["Domain"] == domain and cookie["Name"] == name), None)
        
        if cookie:
            # Prepare the details message with an explanation of the risk score
            details = (
                f"Domain: {cookie['Domain']}\n"
                f"Name: {cookie['Name']}\n"
                f"Expiry: {cookie['Expiry']}\n"
                f"Active: {cookie['Active']}\n"
                f"Persistent: {'Yes' if cookie['Persistent'] else 'No'}\n"
                f"Secure: {'Yes' if cookie['Secure'] else 'No'}\n"
                f"HttpOnly: {'Yes' if cookie['HttpOnly'] else 'No'}\n"
                f"SameSite: {cookie['SameSite']}\n"
                f"Risk Score: {cookie['Risk Score']}\n"
                f"Risks: {cookie['Risks']}\n"
                "\nExplanation of Risk Score:\n"
                f"- Missing Secure flag: {'Yes' if 'Missing Secure flag.' in cookie['Risks'] else 'No'}\n"
                f"- Missing HttpOnly flag: {'Yes' if 'Missing HttpOnly flag.' in cookie['Risks'] else 'No'}\n"
                f"- Invalid SameSite flag: {'Yes' if 'Invalid SameSite flag.' in cookie['Risks'] else 'No'}\n"
            )
            messagebox.showinfo("Cookie Details", details)


# Initialize GUI
root = tk.Tk()
root.title("Persistent Cookie Analyzer")
root.geometry("1200x700")

result_text = tk.StringVar(value="Ready")
analyzed_cookies = []

# Profile Selector
profile_frame = tk.Frame(root)
profile_frame.pack(pady=10)

tk.Label(profile_frame, text="Select Profile:").pack(side=tk.LEFT, padx=5)
profile_combobox = ttk.Combobox(profile_frame, values=get_chrome_profiles(), state="readonly")
profile_combobox.pack(side=tk.LEFT, padx=5)
profile_combobox.set("Default")

tk.Button(profile_frame, text="Extract Cookies", command=lambda: extract_and_display_cookies(profile_combobox.get())).pack(side=tk.LEFT, padx=10)

# Filter Options
filter_frame = tk.Frame(root)
filter_frame.pack(pady=10)

tk.Label(filter_frame, text="Filter by Active Status:").pack(side=tk.LEFT, padx=5)
filter_combobox = ttk.Combobox(filter_frame, values=["All", "Active", "Not Active"], state="readonly")
filter_combobox.pack(side=tk.LEFT, padx=5)
filter_combobox.set("All")

tk.Label(filter_frame, text="Filter by Min Risk Score:").pack(side=tk.LEFT, padx=5)
risk_combobox = ttk.Combobox(filter_frame, values=["All", "1", "2", "3"], state="readonly")
risk_combobox.pack(side=tk.LEFT, padx=5)
risk_combobox.set("All")

tk.Button(filter_frame, text="Apply Filters", command=lambda: extract_and_display_cookies(profile_combobox.get(), filter_combobox.get(), risk_combobox.get())).pack(side=tk.LEFT, padx=10)

# Treeview for Cookies with Scrollbars
tree_frame = tk.Frame(root)
tree_frame.pack(pady=10, fill=tk.BOTH, expand=True)

# Add vertical scrollbar
vertical_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
vertical_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Add horizontal scrollbar
horizontal_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
horizontal_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

tree_columns = ["Checkbox", "Domain", "Name", "Expiry", "Active", "Risk Score", "Risks"]
tree = ttk.Treeview(
    tree_frame,
    columns=tree_columns,
    show="headings",
    selectmode="browse",
    yscrollcommand=vertical_scrollbar.set,
    xscrollcommand=horizontal_scrollbar.set
)

tree.heading("Checkbox", text="Select")
tree.heading("Domain", text="Domain")
tree.heading("Name", text="Name")
tree.heading("Expiry", text="Expiry")
tree.heading("Active", text="Active")
tree.heading("Risk Score", text="Risk Score")
tree.heading("Risks", text="Risks")

tree.column("Checkbox", width=50)
tree.column("Domain", width=150)
tree.column("Name", width=150)
tree.column("Expiry", width=150)
tree.column("Active", width=100)
tree.column("Risk Score", width=100)
tree.column("Risks", width=200)

tree.pack(fill=tk.BOTH, expand=True)

# Configure scrollbars
vertical_scrollbar.config(command=tree.yview)
horizontal_scrollbar.config(command=tree.xview)

# Bind the checkbox column to toggle on click
tree.bind("<ButtonRelease-1>", on_tree_click)
# Bind the double-click event to the treeview
tree.bind("<Double-1>", on_tree_double_click)

# Action Buttons
action_frame = tk.Frame(root)
action_frame.pack(pady=10)

tk.Button(action_frame, text="Select All", command=select_all_cookies).pack(side=tk.LEFT, padx=5)
tk.Button(action_frame, text="Deselect All", command=deselect_all_cookies).pack(side=tk.LEFT, padx=5)
tk.Button(action_frame, text="Delete Selected Cookies", command=lambda: delete_selected_cookies(profile_combobox.get())).pack(side=tk.LEFT, padx=5)
tk.Button(action_frame, text="Generate Report", command=generate_report).pack(side=tk.LEFT, padx=5)

# Status Bar
status_label = tk.Label(root, textvariable=result_text, relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(side=tk.BOTTOM, fill=tk.X)

# Start GUI
root.mainloop()
