import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from scapy.all import ARP, Ether, srp
import socket
import requests
import subprocess
import re
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Tool")
        self.geometry("800x800")
        self.resizable(False, False)
        self.configure(bg="black")
        self.frm = ttk.Frame(self, padding=10)
        self.frm.pack(pady=20)       
        self.label = tk.Label(self, text="Network Tool", font=("Arial", 20), fg="white", bg="black")
        self.label.pack()
        
        self.ipt = tk.Entry(
            self.frm,
            width=50,
            font=("Arial", 20),
            justify="center",
            bd=0,
            insertbackground="white"
        )
        self.ipt.insert(0, "Enter the IP address")
        self.ipt.pack()
        
        self.ping_btn = tk.Button(
            self.frm,
            text="Ping",
            font=("Arial", 20),
            fg="white",
            bg="black",
            command=self.ping_ip
        )
        self.ping_btn.pack(pady=20)
        self.connect_btn = tk.Button(
            self.frm,
            text="Connect",
            font=("Arial", 20),
            fg="white",
            bg="black",
            command=self.connect_to_server
        )
        self.connect_btn.pack(pady=20)
        self.request_btn = tk.Button(
            self.frm,
            text="HTTP Request",
            font=("Arial", 20),
            fg="white",
            bg="black",
            command=self.make_http_request
        )
        self.request_btn.pack(pady=20)
    def validate_ip(self, ip):
        pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        return re.match(pattern, ip)
    def ping_ip(self):
        ip = self.ipt.get().strip()
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address!")
            return
        try:
            result = subprocess.run(["ping", "-c", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Ping Result", f"Host {ip} is up!")
            else:
                messagebox.showinfo("Ping Result", f"Host {ip} is down!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
    def connect_to_server(self):
        ip = self.ipt.get().strip()
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address!")
            return
        try:
            port = 5555
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((ip, port))
                messagebox.showinfo("Connection", f"Successfully connected to {ip} on port {port}!")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
    def make_http_request(self):
        ip = self.ipt.get().strip()
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address!")
            return
        try:
            url = f"http://{ip}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                messagebox.showinfo("HTTP Request", f"Successfully connected to {url}!")
            else:
                messagebox.showinfo("HTTP Request", f"HTTP request failed with status code {response.status_code}.")
        except Exception as e:
            messagebox.showerror("Error", f"HTTP request failed: {e}")
if __name__ == "__main__":
    app = App()
    app.mainloop()



