import os
import hashlib
import subprocess
import sqlite3
from datetime import datetime

# List of known signatures (you can update it based on the latest databases)
known_signatures = [
    '5d41402abc4b2a76b9719d911017c592',  # Example MD5 signature for "hello"
    'e99a18c428cb38d5f260853678922e03'   # Another example MD5 signature for "hello123"
]

def calculate_md5(file_path):
    """Calculate the MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def run_in_sandbox(file_path):
    """Run the file in a sandbox environment and analyze its behavior."""
    try:
        result = subprocess.run(["sandbox-executor", file_path], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"An error occurred while analyzing the file {file_path} in the sandbox environment: {e}")
        return None

def analyze_behavior(file_path):
    """Analyze the file's behavior and return the results."""
    sandbox_output = run_in_sandbox(file_path)
    if sandbox_output:
        if "malicious activity detected" in sandbox_output.lower():
            return True
        else:
            return False
    return None

def scan_file(file_path):
    """Scan a file for known signatures and analyze its behavior."""
    file_signature = calculate_md5(file_path)
    if file_signature in known_signatures:
        return "Known Signature"
    elif analyze_behavior(file_path):
        return "Suspicious Behavior"
    else:
        return "Clean"

def scan_directory(directory_path):
    """Scan an entire directory for infected files."""
    infected_files = []
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            status = scan_file(file_path)
            if status != "Clean":
                infected_files.append((file_path, status))
    return infected_files

def create_database():
    """Create the SQLite database and the results table if they don't exist."""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS results
                 (id INTEGER PRIMARY KEY, file_path TEXT, status TEXT, scan_date TEXT)''')
    conn.commit()
    conn.close()

def store_results(infected_files):
    """Store the scan results in the database."""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    for file_path, status in infected_files:
        c.execute("INSERT INTO results (file_path, status, scan_date) VALUES (?, ?, ?)", 
                  (file_path, status, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def save_results_to_txt(infected_files, filename="scan_results.txt"):
    """Save the scan results to a TXT file."""
    with open(filename, 'a') as f:
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if infected_files:
            for file_path, status in infected_files:
                f.write(f"File: {file_path}, Status: {status}\n")
        else:
            f.write("No suspicious files found.\n")
        f.write("\n")

def display_results():
    """Display the stored scan results."""
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    c.execute("SELECT * FROM results")
    rows = c.fetchall()
    
    if rows:
        print("Scan Results:")
        for row in rows:
            print(f"File: {row[1]}, Status: {row[2]}, Scan Date: {row[3]}")
    else:
        print("No previous scan results found.")
    
    conn.close()

def main():
    create_database()  # Ensure the database and table are created before any operation
    directory_to_scan = input("Enter the path you want to scan: ")
    infected_files = scan_directory(directory_to_scan)
    
    if infected_files:
        print("Suspicious files found:")
        for file_path, status in infected_files:
            print(f"File: {file_path}, Status: {status}")
        
        store_results(infected_files)
        save_results_to_txt(infected_files)  # Save results to TXT file
    else:
        print("No suspicious files found.")
        save_results_to_txt(infected_files)  # Save "No suspicious files" to TXT file
    
    if input("Do you want to view stored scan results? (y/n): ").lower() == 'y':
        display_results()

if __name__ == "__main__":
    main()
