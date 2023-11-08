import tkinter as tk
from tkinter import messagebox
import hashlib
import sqlite3
from tkinter import ttk

app = tk.Tk()
app.title("Resume Generator")
app.geometry("550x450")

app.configure(bg="#042252")

conn = sqlite3.connect('resume_app.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
''')
conn.commit()

def hash_password(password):
    salt = "resume_generator"
    password = password + salt
    return hashlib.sha256(password.encode()).hexdigest()

def register_user():
    username = username_entry.get()
    password = password_entry.get()
    hashed_password = hash_password(password)

    cursor.execute("INSERT INTO Users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()

    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

    if not username or not password:
        messagebox.showerror("Registration Error", "Username and password cannot be empty.")
        return

    messagebox.showinfo("Registration", "Registration successful!")

def login():
    username = login_username_entry.get()
    password = login_password_entry.get()
    hashed_password = hash_password(password)

    cursor.execute("SELECT id FROM Users WHERE username = ? AND password = ?", (username, hashed_password))
    user = cursor.fetchone()

    if not username or not password:
        messagebox.showerror("Login Error", "Username and password cannot be empty.")
        return

    if user:
        messagebox.showinfo("Login", "Login successful!")
        login_username_entry.delete(0, tk.END)
        login_password_entry.delete(0, tk.END)
        app.quit()
    else:
        messagebox.showerror("Login Error", "Invalid credentials!")

# labels
register_label = ttk.Label(app, text="User Registration", font=("Helvetica", 16), background="#042252", foreground="white")
register_label.grid(row=0, column=0, columnspan=2, pady=(20, 10))

username_label = ttk.Label(app, text="Username", font=("Helvetica", 12), background="#042252", foreground="white")
username_label.grid(row=1, column=0, padx=110, pady=10)

password_label = ttk.Label(app, text="Password", font=("Helvetica", 12), background="#042252", foreground="white")
password_label.grid(row=2, column=0, padx=110, pady=10)

login_label = ttk.Label(app, text="User Login", font=("Helvetica", 16), background="#042252", foreground="white")
login_label.grid(row=4, column=0, columnspan=2, pady=(20, 10))

login_username_label = ttk.Label(app, text="Username", font=("Helvetica", 12), background="#042252", foreground="white")
login_username_label.grid(row=5, column=0, padx=110, pady=10)

login_password_label = ttk.Label(app, text="Password", font=("Helvetica", 12), background="#042252", foreground="white")
login_password_label.grid(row=6, column=0, padx=110, pady=10)

#  input fields
username_entry = ttk.Entry(app, font=("Helvetica", 12))
username_entry.grid(row=1, column=1, padx=10, pady=10)

password_entry = ttk.Entry(app, show="*", font=("Helvetica", 12))
password_entry.grid(row=2, column=1, padx=10, pady=10)

login_username_entry = ttk.Entry(app, font=("Helvetica", 12))
login_username_entry.grid(row=5, column=1, padx=10, pady=10)

login_password_entry = ttk.Entry(app, show="*", font=("Helvetica", 12))
login_password_entry.grid(row=6, column=1, padx=10, pady=10)

#  buttons
register_button = ttk.Button(app, text="Register",command=register_user, width=15)
register_button.grid(row=3, column=0, columnspan=2, pady=20)


login_button = ttk.Button(app, text="Login", command=login, width=15)
login_button.grid(row=7, column=0, columnspan=2, pady=20)

app.mainloop()
app.quit()

