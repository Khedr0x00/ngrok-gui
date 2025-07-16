import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import queue
import os
import sys
import time # Import for time.sleep
import requests # Import for making HTTP requests
import json # Import for JSON parsing

class NgrokGUI:
    def __init__(self, master):
        self.master = master
        master.title("Ngrok GUI")
        master.geometry("800x900") # Increased size for more inputs
        master.resizable(True, True) # Allow resizing

        self.ngrok_process = None
        self.log_queue = queue.Queue()
        # Set the default ngrok executable path
        self.ngrok_path = tk.StringVar(value=r"C:\Cyber Security\port\ngrok-v3-stable-windows-amd64\ngrok.exe")

        # Configure the root window's grid to make the main_content_frame expand
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)

        self.create_widgets()
        self.process_log_queue() # Start polling the queue for logs

    def create_widgets(self):
        """Creates all the GUI elements."""
        # Create a main frame to hold all other widgets
        self.main_content_frame = ttk.Frame(self.master, padding="10")
        self.main_content_frame.grid(row=0, column=0, sticky="nsew")

        # Configure grid weights for responsive layout within the main_content_frame
        self.main_content_frame.grid_rowconfigure(0, weight=0) # Ngrok path/auth
        self.main_content_frame.grid_rowconfigure(1, weight=0) # Main options
        self.main_content_frame.grid_rowconfigure(2, weight=0) # Advanced options
        self.main_content_frame.grid_rowconfigure(3, weight=0) # More advanced options
        self.main_content_frame.grid_rowconfigure(4, weight=0) # Buttons
        self.main_content_frame.grid_rowconfigure(5, weight=1) # Log box (should expand)
        self.main_content_frame.grid_columnconfigure(0, weight=1)


        # --- Ngrok Path and Auth Token Frame ---
        ngrok_config_frame = ttk.LabelFrame(self.main_content_frame, text="Ngrok Configuration", padding="10")
        ngrok_config_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
        ngrok_config_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(ngrok_config_frame, text="Ngrok Executable Path:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.ngrok_path_entry = ttk.Entry(ngrok_config_frame, textvariable=self.ngrok_path, width=50)
        self.ngrok_path_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(ngrok_config_frame, text="Browse", command=self.browse_ngrok_path).grid(row=0, column=2, padx=5, pady=2)

        ttk.Label(ngrok_config_frame, text="Auth Token:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.auth_token_entry = ttk.Entry(ngrok_config_frame, width=50, show="*") # Mask token
        self.auth_token_entry.grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        self.auth_token_entry.insert(0, "") # Set default auth token
        ttk.Button(ngrok_config_frame, text="Set Auth Token", command=self.set_authtoken).grid(row=1, column=2, padx=5, pady=2)

        # --- Main Tunnel Options Frame ---
        main_options_frame = ttk.LabelFrame(self.main_content_frame, text="Main Tunnel Options", padding="10")
        main_options_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        main_options_frame.grid_columnconfigure(1, weight=1)
        main_options_frame.grid_columnconfigure(3, weight=1)

        ttk.Label(main_options_frame, text="Protocol:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.protocol_var = tk.StringVar(value="http")
        self.protocol_combo = ttk.Combobox(main_options_frame, textvariable=self.protocol_var,
                                           values=["http", "tcp", "tls"], state="readonly")
        self.protocol_combo.grid(row=0, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(main_options_frame, text="Port/Address:").grid(row=0, column=2, padx=5, pady=2, sticky="w")
        self.port_entry = ttk.Entry(main_options_frame, width=15)
        self.port_entry.grid(row=0, column=3, padx=5, pady=2, sticky="ew")
        self.port_entry.insert(0, "8000") # Default port

        ttk.Label(main_options_frame, text="Subdomain:").grid(row=1, column=0, padx=5, pady=2, sticky="w") # Adjusted row/column
        self.subdomain_entry = ttk.Entry(main_options_frame, width=15)
        self.subdomain_entry.grid(row=1, column=1, padx=5, pady=2, sticky="ew") # Adjusted row/column

        ttk.Label(main_options_frame, text="Hostname:").grid(row=1, column=2, padx=5, pady=2, sticky="w") # Adjusted row/column
        self.hostname_entry = ttk.Entry(main_options_frame, width=15)
        self.hostname_entry.grid(row=1, column=3, padx=5, pady=2, sticky="ew") # Adjusted row/column

        ttk.Label(main_options_frame, text="Auth (user:pass):").grid(row=2, column=0, padx=5, pady=2, sticky="w") # Adjusted row/column
        self.auth_entry = ttk.Entry(main_options_frame, width=15)
        self.auth_entry.grid(row=2, column=1, padx=5, pady=2, sticky="ew") # Adjusted row/column

        # --- Advanced Options Frame ---
        advanced_options_frame = ttk.LabelFrame(self.main_content_frame, text="Advanced Options", padding="10")
        advanced_options_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
        advanced_options_frame.grid_columnconfigure(1, weight=1)
        advanced_options_frame.grid_columnconfigure(3, weight=1)

        ttk.Label(advanced_options_frame, text="Schemes (http,https):").grid(row=0, column=0, padx=5, pady=2, sticky="w") # Adjusted column
        self.schemes_entry = ttk.Entry(advanced_options_frame, width=15)
        self.schemes_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew") # Adjusted column

        ttk.Label(advanced_options_frame, text="Bind TLS:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.bind_tls_var = tk.StringVar(value="") # Can be true, false, both, or empty
        self.bind_tls_combo = ttk.Combobox(advanced_options_frame, textvariable=self.bind_tls_var,
                                           values=["", "true", "false", "both"], state="readonly")
        self.bind_tls_combo.grid(row=1, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(advanced_options_frame, text="Headers (key:value, comma-separated):").grid(row=1, column=2, padx=5, pady=2, sticky="w")
        self.headers_entry = ttk.Entry(advanced_options_frame, width=15)
        self.headers_entry.grid(row=1, column=3, padx=5, pady=2, sticky="ew")

        ttk.Label(advanced_options_frame, text="Metadata:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.metadata_entry = ttk.Entry(advanced_options_frame, width=15)
        self.metadata_entry.grid(row=2, column=1, padx=5, pady=2, sticky="ew")

        # --- Even More Advanced Options Frame ---
        more_advanced_options_frame = ttk.LabelFrame(self.main_content_frame, text="More Advanced Options", padding="10")
        more_advanced_options_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
        more_advanced_options_frame.grid_columnconfigure(1, weight=1)
        more_advanced_options_frame.grid_columnconfigure(3, weight=1)

        self.oauth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(more_advanced_options_frame, text="Enable OAuth", variable=self.oauth_var).grid(row=0, column=0, padx=5, pady=2, sticky="w")
        ttk.Label(more_advanced_options_frame, text="OAuth Provider (google, github, etc.):").grid(row=0, column=1, padx=5, pady=2, sticky="w")
        self.oauth_provider_entry = ttk.Entry(more_advanced_options_frame, width=15)
        self.oauth_provider_entry.grid(row=0, column=2, padx=5, pady=2, sticky="ew")

        ttk.Label(more_advanced_options_frame, text="OAuth Domain:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.oauth_domain_entry = ttk.Entry(more_advanced_options_frame, width=15)
        self.oauth_domain_entry.grid(row=1, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(more_advanced_options_frame, text="OAuth Scope:").grid(row=1, column=2, padx=5, pady=2, sticky="w")
        self.oauth_scope_entry = ttk.Entry(more_advanced_options_frame, width=15)
        self.oauth_scope_entry.grid(row=1, column=3, padx=5, pady=2, sticky="ew")

        self.oauth_allow_emails_var = tk.StringVar(value="") # Comma-separated emails
        ttk.Label(more_advanced_options_frame, text="OAuth Allow Emails:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.oauth_allow_emails_entry = ttk.Entry(more_advanced_options_frame, textvariable=self.oauth_allow_emails_var, width=15)
        self.oauth_allow_emails_entry.grid(row=2, column=1, padx=5, pady=2, sticky="ew")

        self.oauth_allow_globals_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(more_advanced_options_frame, text="OAuth Allow Globals", variable=self.oauth_allow_globals_var).grid(row=2, column=2, padx=5, pady=2, sticky="w")

        self.ip_restrictions_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(more_advanced_options_frame, text="Enable IP Restrictions", variable=self.ip_restrictions_var).grid(row=3, column=0, padx=5, pady=2, sticky="w")
        ttk.Label(more_advanced_options_frame, text="Allow IPs (comma-separated):").grid(row=3, column=1, padx=5, pady=2, sticky="w")
        self.allow_ips_entry = ttk.Entry(more_advanced_options_frame, width=15)
        self.allow_ips_entry.grid(row=3, column=2, padx=5, pady=2, sticky="ew")

        ttk.Label(more_advanced_options_frame, text="Deny IPs (comma-separated):").grid(row=4, column=0, padx=5, pady=2, sticky="w")
        self.deny_ips_entry = ttk.Entry(more_advanced_options_frame, width=15)
        self.deny_ips_entry.grid(row=4, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(more_advanced_options_frame, text="Circuit Breaker (ratio):").grid(row=4, column=2, padx=5, pady=2, sticky="w")
        self.circuit_breaker_entry = ttk.Entry(more_advanced_options_frame, width=15)
        self.circuit_breaker_entry.grid(row=4, column=3, padx=5, pady=2, sticky="ew")

        ttk.Label(more_advanced_options_frame, text="Websocket Ping Timeout (duration, e.g., 5s):").grid(row=5, column=0, padx=5, pady=2, sticky="w")
        self.websocket_ping_timeout_entry = ttk.Entry(more_advanced_options_frame, width=15)
        self.websocket_ping_timeout_entry.grid(row=5, column=1, padx=5, pady=2, sticky="ew")


        # --- Buttons Frame ---
        button_frame = ttk.Frame(self.main_content_frame, padding="10")
        button_frame.grid(row=4, column=0, padx=10, pady=5, sticky="ew")
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_columnconfigure(2, weight=1)

        self.connect_button = ttk.Button(button_frame, text="Connect Ngrok", command=self.start_ngrok)
        self.connect_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.disconnect_button = ttk.Button(button_frame, text="Disconnect Ngrok", command=self.stop_ngrok, state=tk.DISABLED)
        self.disconnect_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.clear_log_button = ttk.Button(button_frame, text="Clear Log", command=self.clear_log)
        self.clear_log_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        # --- Log Output Frame ---
        log_frame = ttk.LabelFrame(self.main_content_frame, text="Ngrok Log Output", padding="10")
        log_frame.grid(row=5, column=0, padx=10, pady=5, sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=80, height=20, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

    def browse_ngrok_path(self):
        """Opens a file dialog to select the ngrok executable."""
        file_path = filedialog.askopenfilename(
            title="Select Ngrok Executable",
            filetypes=[("Executables", "*"), ("All Files", "*.*")]
        )
        if file_path:
            self.ngrok_path.set(file_path)

    def set_authtoken(self):
        """Sets the ngrok authtoken."""
        ngrok_exe = self.ngrok_path.get().strip()
        auth_token = self.auth_token_entry.get().strip()

        if not ngrok_exe:
            messagebox.showerror("Error", "Please specify the ngrok executable path.")
            return
        if not os.path.exists(ngrok_exe):
            messagebox.showerror("Error", f"Ngrok executable not found at: {ngrok_exe}")
            return
        if not auth_token:
            messagebox.showwarning("Warning", "Auth token is empty. Ngrok might not connect to your account.")
            return

        try:
            self.log_message(f"Setting ngrok authtoken...")
            # Use shell=True for simpler command execution, but be cautious with untrusted input
            # Here, input is controlled by the app, so it's relatively safe.
            command = [ngrok_exe, "authtoken", auth_token]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.log_message(result.stdout)
            self.log_message(result.stderr)
            if result.returncode == 0:
                messagebox.showinfo("Success", "Ngrok authtoken set successfully!")
            else:
                messagebox.showerror("Error", f"Failed to set authtoken: {result.stderr}")
        except FileNotFoundError:
            messagebox.showerror("Error", f"Ngrok executable not found at: {ngrok_exe}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error setting authtoken: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def start_ngrok(self):
        """Constructs the ngrok command and starts the tunnel."""
        if self.ngrok_process:
            messagebox.showwarning("Warning", "Ngrok is already running. Please disconnect first.")
            return

        ngrok_exe = self.ngrok_path.get().strip()
        if not ngrok_exe:
            messagebox.showerror("Error", "Please specify the ngrok executable path.")
            return
        if not os.path.exists(ngrok_exe):
            messagebox.showerror("Error", f"Ngrok executable not found at: {ngrok_exe}")
            return

        protocol = self.protocol_var.get()
        port_or_address = self.port_entry.get().strip()
        subdomain = self.subdomain_entry.get().strip()
        hostname = self.hostname_entry.get().strip()
        auth = self.auth_entry.get().strip()
        schemes = self.schemes_entry.get().strip()
        bind_tls = self.bind_tls_var.get().strip()
        headers = self.headers_entry.get().strip()
        metadata = self.metadata_entry.get().strip()

        oauth_enabled = self.oauth_var.get()
        oauth_provider = self.oauth_provider_entry.get().strip()
        oauth_domain = self.oauth_domain_entry.get().strip()
        oauth_scope = self.oauth_scope_entry.get().strip()
        oauth_allow_emails = self.oauth_allow_emails_var.get().strip()
        oauth_allow_globals = self.oauth_allow_globals_var.get()

        ip_restrictions_enabled = self.ip_restrictions_var.get()
        allow_ips = self.allow_ips_entry.get().strip()
        deny_ips = self.deny_ips_entry.get().strip()

        circuit_breaker = self.circuit_breaker_entry.get().strip()
        websocket_ping_timeout = self.websocket_ping_timeout_entry.get().strip()

        if not port_or_address:
            messagebox.showerror("Error", "Please enter a Port or Address.")
            return

        command = [ngrok_exe, protocol, port_or_address]

        if subdomain:
            command.extend(["--subdomain", subdomain])
        if hostname:
            command.extend(["--hostname", hostname])
        if auth:
            command.extend(["--auth", auth])
        if schemes:
            command.extend(["--schemes", schemes])
        if bind_tls:
            command.extend(["--bind-tls", bind_tls])
        if headers:
            for header in headers.split(','):
                if header.strip():
                    command.extend(["--header", header.strip()])
        if metadata:
            command.extend(["--metadata", metadata])

        if oauth_enabled:
            if not oauth_provider:
                messagebox.showwarning("Warning", "OAuth enabled but no provider specified. Ngrok might default or error.")
            command.extend(["--oauth", oauth_provider])
            if oauth_domain:
                command.extend(["--oauth-domain", oauth_domain])
            if oauth_scope:
                command.extend(["--oauth-scope", oauth_scope])
            if oauth_allow_emails:
                command.extend(["--oauth-allow-emails", oauth_allow_emails])
            if oauth_allow_globals:
                command.append("--oauth-allow-globals")

        if ip_restrictions_enabled:
            if allow_ips:
                command.extend(["--allow-ips", allow_ips])
            if deny_ips:
                command.extend(["--deny-ips", deny_ips])
            if not allow_ips and not deny_ips:
                messagebox.showwarning("Warning", "IP Restrictions enabled but no allow/deny IPs specified.")

        if circuit_breaker:
            try:
                float(circuit_breaker)
                command.extend(["--circuit-breaker", circuit_breaker])
            except ValueError:
                messagebox.showwarning("Warning", "Invalid Circuit Breaker value. Must be a number.")

        if websocket_ping_timeout:
            command.extend(["--websocket-ping-timeout", websocket_ping_timeout])


        self.log_message(f"Starting ngrok with command: {' '.join(command)}")
        try:
            self.ngrok_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, # Decode stdout/stderr as text
                bufsize=1, # Line-buffered output
                universal_newlines=True # Ensure consistent newline handling
            )
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.NORMAL)

            # Start a thread to read ngrok's output
            self.ngrok_thread = threading.Thread(target=self.run_ngrok_in_thread, daemon=True)
            self.ngrok_thread.start()

            # Start a separate thread to fetch the public URL via ngrok API
            self.url_fetch_thread = threading.Thread(target=self.fetch_public_url_from_api, daemon=True)
            self.url_fetch_thread.start()

        except FileNotFoundError:
            messagebox.showerror("Error", f"Ngrok executable not found at: {ngrok_exe}\nPlease ensure the path is correct and ngrok is installed.")
            self.log_message(f"Error: Ngrok executable not found at: {ngrok_exe}")
            self.connect_button.config(state=tk.NORMAL)
            self.disconnect_button.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start ngrok: {e}")
            self.log_message(f"Error: Failed to start ngrok: {e}")
            self.connect_button.config(state=tk.NORMAL)
            self.disconnect_button.config(state=tk.DISABLED)

    def run_ngrok_in_thread(self):
        """Reads output from the ngrok process and puts it into a queue."""
        if self.ngrok_process:
            for line in self.ngrok_process.stdout:
                self.log_queue.put(line)
            self.ngrok_process.stdout.close()

            # Also read stderr
            for line in self.ngrok_process.stderr:
                self.log_queue.put(f"ERROR: {line}")
            self.ngrok_process.stderr.close()

            self.ngrok_process.wait() # Wait for the process to terminate
            self.log_queue.put("Ngrok process terminated.")
            self.master.after(0, self.on_ngrok_terminated) # Schedule GUI update on main thread

    def fetch_public_url_from_api(self):
        """Fetches the public URL from the ngrok API."""
        api_url = "http://127.0.0.1:4040/api/tunnels"
        max_attempts = 10
        delay_seconds = 1

        for attempt in range(max_attempts):
            if not self.ngrok_process or self.ngrok_process.poll() is not None:
                self.log_queue.put("Ngrok process not running, cannot fetch URL from API.")
                return

            try:
                response = requests.get(api_url, timeout=5)
                response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                tunnels_data = response.json()

                if tunnels_data and "tunnels" in tunnels_data and len(tunnels_data["tunnels"]) > 0:
                    # Assuming we want the first tunnel's public URL
                    public_url = tunnels_data["tunnels"][0]["public_url"]
                    self.log_queue.put(f"Public URL: {public_url}")
                    return
                else:
                    self.log_queue.put(f"Attempt {attempt + 1}/{max_attempts}: No tunnels found yet. Retrying...")
            except requests.exceptions.ConnectionError:
                self.log_queue.put(f"Attempt {attempt + 1}/{max_attempts}: Ngrok API not yet available. Retrying...")
            except requests.exceptions.Timeout:
                self.log_queue.put(f"Attempt {attempt + 1}/{max_attempts}: Ngrok API connection timed out. Retrying...")
            except json.JSONDecodeError:
                self.log_queue.put(f"Attempt {attempt + 1}/{max_attempts}: Failed to decode JSON from Ngrok API. Retrying...")
            except requests.exceptions.RequestException as e:
                self.log_queue.put(f"Attempt {attempt + 1}/{max_attempts}: Error fetching Ngrok API: {e}. Retrying...")
            except Exception as e:
                self.log_queue.put(f"Attempt {attempt + 1}/{max_attempts}: An unexpected error occurred while fetching URL: {e}. Retrying...")

            time.sleep(delay_seconds) # Wait before retrying

        self.log_queue.put("Failed to retrieve public URL from Ngrok API after multiple attempts.")


    def on_ngrok_terminated(self):
        """Called on the main thread when ngrok process terminates."""
        self.ngrok_process = None
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)

    def stop_ngrok(self):
        """Stops the ngrok tunnel."""
        if self.ngrok_process:
            self.log_message("Stopping ngrok process...")
            try:
                # Terminate the process gracefully
                self.ngrok_process.terminate()
                # Wait a short period for it to terminate
                try:
                    self.ngrok_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.log_message("Ngrok process did not terminate gracefully, forcing kill...")
                    self.ngrok_process.kill() # Force kill if it doesn't terminate
                self.log_message("Ngrok process stopped.")
            except Exception as e:
                self.log_message(f"Error stopping ngrok: {e}")
            finally:
                self.ngrok_process = None
                self.connect_button.config(state=tk.NORMAL)
                self.disconnect_button.config(state=tk.DISABLED)
        else:
            messagebox.showinfo("Info", "Ngrok is not running.")

    def log_message(self, message):
        """Inserts a message into the log text area."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END) # Scroll to the end
        self.log_text.config(state=tk.DISABLED)

    def process_log_queue(self):
        """Checks the queue for new log messages and updates the GUI."""
        while not self.log_queue.empty():
            line = self.log_queue.get_nowait()
            self.log_message(line.strip())
        self.master.after(100, self.process_log_queue) # Check again after 100ms

    def clear_log(self):
        """Clears the content of the log text area."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def on_closing(self):
        """Handles window closing event, ensures ngrok process is stopped."""
        if self.ngrok_process:
            self.stop_ngrok()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NgrokGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing) # Handle window close event
    root.mainloop()
