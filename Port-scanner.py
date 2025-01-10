import socket
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog
import threading


# Function to scan TCP ports
def scan_tcp_ports(ip, start_port, end_port, results, progress_var):
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service_name = socket.getservbyport(port, "tcp") if port < 65536 else "Unknown Service"
                results.append(f"TCP Port {port} is open - {service_name}")
            sock.close()
        except Exception as e:
            results.append(f"Error scanning TCP port {port}: {str(e)}")

        # Update progress
        progress_var.set((port - start_port + 1) / (end_port - start_port + 1) * 100)


# Function to scan UDP ports with error handling
def scan_udp_ports(ip, start_port, end_port, results, progress_var):
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(b"Hello", (ip, port))
            sock.recvfrom(1024)
            service_name = socket.getservbyport(port, "udp") if port < 65536 else "Unknown Service"
            results.append(f"UDP Port {port} is open - {service_name}")
        except socket.timeout:
            continue
        except ConnectionResetError:
            continue
        except OSError as e:
            if e.errno == 10054:
                continue
            else:
                results.append(f"Error scanning UDP port {port}: {str(e)}")

        # Update progress
        progress_var.set((port - start_port + 1) / (end_port - start_port + 1) * 100)


# Function to update the GUI with scan results
def update_results(results, result_text):
    result_text.delete(1.0, tk.END)
    if results:
        result_text.insert(tk.END, "\n".join(results))
    else:
        result_text.insert(tk.END, "No open ports found.")


# Function to save results to a file
def save_results(results):
    if not results:
        messagebox.showerror("Error", "No results to save!")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write("\n".join(results))
        messagebox.showinfo("Success", "Results saved successfully!")


# Function to start the scanning process
def start_scan(ip, start_port, end_port, result_text, progress_var):
    try:
        ip = ip_entry.get()
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())

        # Validate port range
        if start_port > end_port or start_port < 1 or end_port > 65535:
            messagebox.showerror("Error", "Please enter a valid port range (1-65535)!")
            return

        results = []

        # Create and start threads for TCP and UDP scanning
        tcp_thread = threading.Thread(target=scan_tcp_ports, args=(ip, start_port, end_port, results, progress_var))
        udp_thread = threading.Thread(target=scan_udp_ports, args=(ip, start_port, end_port, results, progress_var))

        tcp_thread.start()
        udp_thread.start()

        # Monitor threads and update results when both finish
        def monitor_threads():
            if tcp_thread.is_alive() or udp_thread.is_alive():
                root.after(100, monitor_threads)
            else:
                update_results(results, result_text)

        monitor_threads()

    except ValueError:
        messagebox.showerror("Error", "Please enter valid port numbers!")


# GUI setup
root = tk.Tk()
root.title("Port Scanner")

# Input fields
tk.Label(root, text="IP Address:").grid(row=0, column=0)
ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1)

tk.Label(root, text="Start Port:").grid(row=1, column=0)
start_port_entry = tk.Entry(root)
start_port_entry.grid(row=1, column=1)

tk.Label(root, text="End Port:").grid(row=2, column=0)
end_port_entry = tk.Entry(root)
end_port_entry.grid(row=2, column=1)

# Progress bar
progress_var = tk.DoubleVar()
progress_bar = tk.ttk.Progressbar(root, variable=progress_var, maximum=100)
progress_bar.grid(row=3, column=0, columnspan=2, pady=10, sticky="we")

# Start button
scan_button = tk.Button(root, text="Start Scan",
                        command=lambda: start_scan(ip_entry.get(), start_port_entry.get(), end_port_entry.get(),
                                                   result_text, progress_var))
scan_button.grid(row=4, column=0, columnspan=2)

# Save button
save_button = tk.Button(root, text="Save Results", command=lambda: save_results(results=[]))
save_button.grid(row=5, column=0, columnspan=2)

# Results field
result_text = tk.Text(root, height=15, width=50)
result_text.grid(row=6, column=0, columnspan=2)

# Run the GUI
root.mainloop()
