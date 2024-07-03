import tkinter as tk
from tkinter import filedialog
import main 
import time

def browse_folder():
    global directory
    directory = filedialog.askdirectory()

    if directory:
        
        folder_path_label.config(text=f"Selected Folder: {directory}", font = font)
        scan_button.pack(pady=10)

def scan_files():
    scan_button.config(text = "Scanning...")
    

    file_listbox.pack(side=tk.TOP, fill=tk.Y)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    file_listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=file_listbox.yview)

    lis = main.all_paths_scan(directory)
    for i in lis:
        file_listbox.insert(tk.END, i)
        
    scan_button.config(text = "Scan Complete")

window = tk.Tk()

window.title("Anti Virus")
window.geometry("300x400")

font = ("Arial", 14)

folder_path_label = tk.Label(text="No folder selected yet.", font = font)
folder_path_label.pack()

browse_button = tk.Button(text="Browse Folder", command=browse_folder, font=font)
browse_button.pack(pady=10)

file_listbox = tk.Listbox(window)
file_listbox.config(width=50, height=10)
scrollbar = tk.Scrollbar(window, orient=tk.VERTICAL)

scan_button = tk.Button(text="Start Scan",command =scan_files  ,font = font)

window.mainloop()