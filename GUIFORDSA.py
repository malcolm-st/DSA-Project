import tkinter as tk
import tkinter.ttk as ttk
from tkinter import font, filedialog, messagebox, simpledialog, ttk, Scrollbar
import docx
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import csv

# retrieve imports
import git
import os
import subprocess
import shutil
from tqdm import tqdm
from threading import Thread

# update imports
import requests
from bs4 import BeautifulSoup
import zipfile
import io
import time
import threading

# json to csv imports
import json

# for URL openings
import webbrowser

from tkinter import *
from SystemChecker import *
from VendorAnalysis import *
from UpdateCVE import *

# Global flag variable
is_program_running = True

# Clone the repository to a local folder
repo_url = "https://github.com/CVEProject/cvelistV5.git"
local_folder = "scrapedCVE"

bar_chart_created = False
bar_chart = None

# def merge_sort(arr):
#     if len(arr) <= 1:
#         return arr

#     mid = len(arr) // 2
#     left = arr[:mid]
#     right = arr[mid:]

#     left = merge_sort(left)
#     right = merge_sort(right)

#     return merge(left, right)

# def merge(left, right):
#     merged = []
#     i = j = 0

#     while i < len(left) and j < len(right):
#         if left[i][1] > right[j][1]:
#             merged.append(left[i])
#             i += 1
#         else:
#             merged.append(right[j])
#             j += 1

#     merged.extend(left[i:])
#     merged.extend(right[j:])

#     return merged

# Pull CVE database
def pull_cves(progress_bar):
    git.Repo.clone_from(repo_url, local_folder)
    progress_bar.update(1)

# Delete directories/files
def remove_folders_files(directory, progress_bar):
    # Iterate over all items in the directory
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)
        # If the item is a file
        if os.path.isfile(item_path):
            # Remove the file
            os.remove(item_path)
        # If the item is a directory
        else:
            # Check if the directory is not "cves"
            if item != "cves":
                # Construct the system command to remove directories
                command = 'rd /s /q "{}"'.format(item_path)
                # Execute the command using subprocess
                subprocess.run(command, shell=True)
    progress_bar.update(1)

def move_files(source_directory, destination_directory, progress_bar):
    if not os.path.exists("compiledCVE"):
        os.makedirs("compiledCVE")

    # Retrieve the list of items in the source directory
    items = os.listdir(source_directory)

    # Iterate over all items in the source directory
    for item in items:
        item_path = os.path.join(source_directory, item)
        # Check if the item is a file
        if os.path.isfile(item_path):
            # Move the file to the destination directory
            shutil.move(item_path, destination_directory)
        # Check if the item is a directory
        elif os.path.isdir(item_path):
            # Recursively move files in the sub-directory
            move_files(item_path, destination_directory, progress_bar)

# def move_files_update(source_directory, destination_directory):
#     # if not os.path.exists("testmove"):
#     #     os.makedirs("testmove")

#     # Iterate over all items in the source directory
#     for item in os.listdir(source_directory):
#         item_path = os.path.join(source_directory, item)
#         # Check if the item is a file
#         if os.path.isfile(item_path):
#             # Remove the existing file in the destination directory if it exists
#             destination_path = os.path.join(destination_directory, item)
#             if os.path.exists(destination_path):
#                 os.remove(destination_path)
#             # Move the file to the destination directory
#             shutil.move(item_path, destination_directory)
#         # Check if the item is a directory
#         elif os.path.isdir(item_path):
#             # Recursively move files in the sub-directory
#             move_files_update(item_path, destination_directory)

# def update_csv_from_json():
#     json_folder = 'updatedCVE/deltaCves'
#     csv_file = 'CVECSV.csv'

#     csv_data = []  # List to store the CSV data

#     # Check if the CSV file exists
#     csv_exists = os.path.exists(csv_file)

#     # Read existing CSV data if the file exists
#     if csv_exists:
#         with open(csv_file, 'r', encoding='utf-8') as file:
#             reader = csv.reader(file)
#             csv_data = list(reader)

#     # Check if the last row is the header row only
#     last_row_header_only = csv_exists and csv_data and csv_data[0][0] == 'CveID'

#     for filename in os.listdir(json_folder):
#         if filename.endswith('.json'):
#             cve_id = filename.split('.')[0]
#             json_file = os.path.join(json_folder, filename)

#             with open(json_file, 'r', encoding='utf-8') as json_data:
#                 data = json.load(json_data)

#             # Access affected vendors
#             affected_vendors = data.get('containers', {}).get('cna', {}).get('affected', [])
#             vendor = affected_vendors[0].get('vendor', '') if affected_vendors else ''

#             # Access base score
#             metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
#             score = metrics[0].get('cvssV3_0', {}).get('baseScore', '') if metrics else ''

#             # Access description value
#             descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
#             description = descriptions[0].get('value', '') if descriptions else ''

#             # Check if CveID already exists in CSV data
#             cve_exists = False
#             for row in csv_data:
#                 if row[0] == cve_id:
#                     row[1] = vendor
#                     row[2] = score
#                     row[3] = description
#                     cve_exists = True
#                     break

#             # If CveID doesn't exist, create a new row
#             if not cve_exists:
#                 new_row = [cve_id, vendor, score, description]
#                 csv_data.append(new_row)

#     # Add headers at the top of the CSV data if necessary
#     if not last_row_header_only:
#         csv_data.insert(0, ['CveID', 'Vendor', 'Score', 'Description'])

#     # Write the updated CSV data back to the file
#     with open(csv_file, 'w', newline='', encoding='utf-8') as file:
#         writer = csv.writer(file)
#         writer.writerows(csv_data)

# def update_cve():
#     # Define the URL and CSS selector
#     url = "https://github.com/CVEProject/cvelistV5/releases"
#     selector = "#repo-content-pjax-container > div > div:nth-child(3) > section:nth-child(1) > div > div.col-md-9 > div > div.Box-body > div.d-flex.flex-md-row.flex-column > div.d-flex.flex-row.flex-1.mb-3.wb-break-word > div.flex-1 > span > a"

#     # Send a GET request to the URL
#     response = requests.get(url)

#     # Parse the HTML content with BeautifulSoup
#     soup = BeautifulSoup(response.content, "html.parser")

#     # Find the element that matches the selector and get the href attribute
#     element = soup.select_one(selector)
#     if element is not None:
#         href = element.get("href")
#         # print(href)
#     else:
#         print(f"No element found for CSS selector: {selector}")

#     # Splicing of href attribute to create download link to download updated CVEs in .zip file
#     spliced_output = href[35:]
#     # print(spliced_output)

#     year = spliced_output[4:8]
#     # print(year)

#     month = spliced_output[9:11]
#     # print(month)

#     day = spliced_output[12:14]
#     # print(day)

#     timeStamp = spliced_output[-5:]
#     # print(timeStamp)

#     downloadLink = "https://github.com/CVEProject/cvelistV5/releases/download/" + spliced_output + "/" + year + "-" + month + "-" + day + "_delta_CVEs_at_" + timeStamp + ".zip"
#     # print(downloadLink)

#     fileName = year + "-" + month + "-" + day + "_delta_CVEs_at_" + timeStamp + ".zip"
#     # print(fileName)

#     # Send a GET request to the URL and get the ZIP file content
#     response = requests.get(downloadLink)
#     zip_content = io.BytesIO(response.content)

#     if not os.path.exists("updatedCVE"):
#         os.makedirs("updatedCVE")

#     # Extract the contents of the ZIP file to a directory
#     with zipfile.ZipFile(zip_content, "r") as zip_ref:
#         zip_ref.extractall("updatedCVE")

#     # Update CVECSV.csv file
#     update_csv_from_json()

#     # Update compiledCVE folder
#     # Overwrites updated CVE files into compiledCVE folder
#     move_files_update("updatedCVE/deltaCves", "compiledCVE")

#     # Removes original updatedCVE folder
#     shutil.rmtree("updatedCVE")

# # Indefinitely check for updates
# def check_for_updates():
#     # Define the repository details
#     username = "CVEProject"
#     repository = "cvelistV5"
#     branch = "main"

#     # Define the API endpoint and headers
#     api_endpoint = f"https://api.github.com/repos/{username}/{repository}/branches/{branch}"
#     headers = {"Accept": "application/vnd.github.v3+json",
#                "Authorization": "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"}

#     # Initialize the last commit hash
#     last_commit_hash = None

#     # Loop indefinitely to check for updates
#     while is_program_running:
#         # Send a GET request to the API endpoint to get branch details
#         response = requests.get(api_endpoint, headers=headers)

#         # Check if the response is successful
#         if response.ok:
#             # Get the latest commit hash
#             commit_hash = response.json()["commit"]["sha"]

#             print("Checking Repo for commit hash")

#             # Check if this is the first loop or if the commit hash has changed
#             if last_commit_hash is None or commit_hash != last_commit_hash:
#                 print("Updating Local Database")
#                 # Update the local folder
#                 update_cve()

#                 # Update the last commit hash
#                 last_commit_hash = commit_hash

#                 # Log the update
#                 print(f"Updated local folder withnew changes from GitHub repository. Commit hash: {commit_hash}")

#         else:
#             # Log the error
#             print(f"Error checking for updates: {response.status_code} {response.reason}")

#         # Wait for 1 hour before checking again
#         # time.sleep(3600)

#         # Updates Database every minute
#         time.sleep(60)

# # Function to call the check_for_updates function in a separate thread so GUI will not crash
# def run_update_checker():
#     thread = threading.Thread(target=check_for_updates)
#     thread.start()

# def json_to_csv(json_folder, csv_file):
#     # List all JSON files in the folder
#     json_files = [file for file in os.listdir(json_folder) if file.endswith('.json')]

#     with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
#         writer = csv.writer(csvfile)

#         # Write header
#         writer.writerow(['CveID', 'Vendor', 'Score', 'Description'])

#         # Start the timer
#         start_time =  time.time()
#         # Process each JSON file
#         for json_file in json_files:
#             with open(os.path.join(json_folder, json_file), encoding='utf-8') as file:
#                 try:
#                     data = json.load(file)
#                     cve_id = data.get('cveMetadata', {}).get('cveId', '')
                    
#                     # Access affected vendors
#                     affected_vendors = data.get('containers', {}).get('cna', {}).get('affected', [])
#                     vendor = affected_vendors[0].get('vendor', '') if affected_vendors else ''
                    
#                     # Access base score
#                     metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
#                     score = metrics[0].get('cvssV3_0', {}).get('baseScore', '') if metrics else ''
                    
#                     # Access description value
#                     descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
#                     description = descriptions[0].get('value', '') if descriptions else ''
                    
#                     writer.writerow([cve_id, vendor, score, description])
#                 except:
#                     print(f"Error has occurred while processing {json_file}. Skipping the file.")
    
#     # Calculate elapsed time
#     elapsed_time = time.time() - start_time
#     print(f"Data extraction complete. Elapsed time: {elapsed_time:.2f} seconds.")


def upload():
    file_path = filedialog.askopenfilename(filetypes=[("Word Documents", "*.docx")])
    if file_path:
        if file_path.endswith(".docx"):
            display_docx_content(file_path)
        else:
            print("Invalid file format. Please upload a DOCX file.")

# def upload():
#     file_path = filedialog.askopenfilename(filetypes=[("Word Documents", "*.docx"), ("Text Files", "*.txt")])
#     if file_path:
#         if file_path.endswith(".docx"):
#             search_csv_by_id(file_path, 'D:/SIT/Y1S3/INF1008/Project/output.csv')
#         elif file_path.endswith(".txt"):
#             search_csv_by_id(file_path, 'D:/SIT/Y1S3/INF1008/Project/output.csv')
#         else:
#             print("Invalid file format. Please upload a DOCX or TXT file.")

def display_docx_content(file_path):
    doc = docx.Document(file_path)
    paragraphs = [paragraph.text for paragraph in doc.paragraphs]
    file_content = "\n".join(paragraphs)

    new_window = tk.Toplevel(root)
    new_window.title("DOCX Content")

    screen_width = new_window.winfo_screenwidth()
    screen_height = new_window.winfo_screenheight()

    content_text = tk.Text(new_window, bg="#f2f2f2", font=button_font, padx=10, pady=10)
    content_text.insert(tk.END, file_content)
    content_text.pack(fill="both", expand=True)


def update():
    print("Update button clicked")

    # check_for_updates() will update CVEs properly, but GUI will not respond due to while loop
    # Use threading to call the function instead, run_update_checker()
    run_update_checker()

    # Testing updating csv file from .json updates file
    # update_csv_from_json()


def retrieve_data():
    print("Retrieve Data button clicked")
    # Create a progress bar
    total_steps = 4
    progress_bar = tqdm(total=total_steps, unit="step")

    if not os.path.exists("scrapedCVE"):
        os.makedirs("scrapedCVE")

    # Retrieve CVEs from database
    pull_cves(progress_bar)

    # Call the function to remove folders and files
    remove_folders_files(local_folder, progress_bar)

    # Call the function to move files
    move_files("scrapedCVE/cves", "compiledCVE", progress_bar)

    # Removes original scrapedCVE folder
    shutil.rmtree("scrapedCVE")
    progress_bar.update(1)

    # Convert .json files into a single CVECSV.csv files
    # Provide the folder containing JSON files and the desired CSV file
    dir_path = os.path.dirname(os.path.realpath(__file__))
    json_filename = 'compiledCVE'
    csv_filename = 'CVECSV.csv'
    json_folder = os.path.join(dir_path, json_filename)
    csv_file = os.path.join(dir_path, csv_filename)

    json_to_csv(json_folder, csv_file)

    progress_bar.update(1)

    # Close the progress bar
    progress_bar.close()

    # Signal that the retrieval process is complete
    retrieval_complete.set(True)

def check_retrieval_status():
    if retrieval_complete.get():
        # Show success message
        success_label.config(text="Retrieve Data Successful")
        # Destroy the loading window
        loading_window.destroy()
    else:
        # Continue checking the status after 100ms
        root.after(100, check_retrieval_status)

def open_loading_window():
    global loading_window, success_label, retrieval_complete
    loading_window = tk.Toplevel(root)
    loading_window.title("Loading...")
    loading_window.geometry("400x100")
    loading_window.resizable(False, False)

    progress_label = ttk.Label(loading_window, text="Retrieving data...")
    progress_label.pack(pady=10)

    progress_bar = ttk.Progressbar(loading_window, mode="indeterminate", length=350)
    progress_bar.pack(pady=10)
    progress_bar.start()

    success_label = ttk.Label(loading_window, text="")
    success_label.pack(pady=10)

    retrieval_complete = tk.BooleanVar()
    retrieval_complete.set(False)

    loading_thread = Thread(target=retrieve_data)
    loading_thread.start()

    check_retrieval_status()

def show_page(page):
    page.tkraise()

root = tk.Tk()
root.title("CVE Aggregator")


# Get the screen width and height
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate the font size based on the screen height
title_font_size = int(screen_height / 20)
button_font_size = int(screen_height / 40)

# Create custom fonts with the calculated sizes
title_font = font.Font(size=title_font_size, weight="bold")
button_font = font.Font(size=button_font_size)

# Create a Frame to hold the pages
page_frame = tk.Frame(root)
page_frame.pack(fill="both", expand=True)

# Create the Home page
home_page = tk.Frame(page_frame, bg="#f2f2f2")
home_page.pack(fill="both", expand=True)

welcome_label = tk.Label(home_page, text="Welcome to CVE Aggregator", font=title_font, wraplength=screen_width - 100,  bg="#f2f2f2")
welcome_label.pack(pady=20)

# Configure button styles
button_style = {
    "bg": "#4CAF50",
    "fg": "white",
    "activebackground": "#45a049",
    "activeforeground": "white",
    "bd": 0,
    "width": 20,
    "font": button_font,
    "pady": 10
}

update_button = tk.Button(home_page, text="Update", command=update, **button_style)
update_button.pack(pady=10)

retrieve_button = tk.Button(home_page, text="Retrieve Data", command=open_loading_window, **button_style)
retrieve_button.pack(pady=10)

# def check_windows_defender_settings():
#     try:
#         output = subprocess.check_output('powershell -Command "(Get-MpPreference).DisableRealtimeMonitoring"', shell=True)
#         output = output.decode('utf-8').strip()
#         if output.lower() == 'false':
#             return "Windows Defender Real-time Monitoring: Enabled"
#         else:
#             return "Windows Defender Real-time Monitoring: Disabled"
#     except subprocess.CalledProcessError:
#         return "Error occurred while checking Windows Defender settings."

# def check_firewall_settings():
#     try:
#         output = subprocess.check_output('powershell -Command "(Get-NetFirewallProfile).Enabled"', shell=True)
#         output = output.decode('utf-8').strip()

#         firewall_profiles = {
#             'Domain': False,
#             'Private': False,
#             'Public': False
#         }

#         if 'True' in output:
#             enabled_profiles = subprocess.check_output('powershell -Command "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $True}).Name"', shell=True)
#             enabled_profiles = enabled_profiles.decode('utf-8').strip()
#             enabled_profiles = enabled_profiles.split('\n')

#             for profile in enabled_profiles:
#                 profile = profile.strip()
#                 if profile in firewall_profiles:
#                     firewall_profiles[profile] = True

#         result = "Firewall Settings:\n"
#         for profile, enabled in firewall_profiles.items():
#             if enabled:
#                 result += f"{profile}: Enabled\n"
#             else:
#                 result += f"{profile}: Disabled\n"

#         return result
#     except subprocess.CalledProcessError:
#         return "Error occurred while checking firewall settings."

# System Security Checker Page
def show_toolcheck_page():
    print("Tool Page clicked")

    for child in page_frame.winfo_children():
        child.pack_forget()
    home_page.pack_forget()
    label_cvesearch.pack_forget()
    label_analysis.pack_forget()
    label_toolcheck.pack(pady=20, side="top")
    toolcheck.pack(fill="both", expand=True)

    windows_defender_result = check_windows_defender_settings()
    firewall_result = check_firewall_settings()
    
    label_toolcheck.config(text=f"Windows Defender Status:\n{windows_defender_result}\n\n{firewall_result}", font=("Arial", 40))


#############################################################################################
#######################                                            ##########################
#######################        Display CSV Data for App            ##########################
#######################                                            ##########################
#############################################################################################

def display_csv_data(data):
    # Clear existing data in Treeview
    show_cvesearch_page.results_tree.delete(*show_cvesearch_page.results_tree.get_children())

    header = ['CveID', 'Vendor', 'Score', 'Description']
    show_cvesearch_page.results_tree["columns"] = header

    # Configure column names and properties
    column_widths = [10, 10, 10, 400]  # Specify the width for each column
    column_min_widths = [100, 100, 100, 2500]  # Specify the minimum width for each column

    for i, col in enumerate(header):
        show_cvesearch_page.results_tree.heading(col, text=col)
        show_cvesearch_page.results_tree.column(col, width=column_widths[i], minwidth=column_min_widths[i])

    # Populate the Treeview with data rows
    for row in data[1:]:
        show_cvesearch_page.results_tree.insert("", tk.END, values=row)


    
def show_cvesearch_page():
    # Clear previous contents of the page
    for child in page_frame.winfo_children():
        child.pack_forget()

    home_page.pack_forget()
    label_analysis.pack_forget()
    label_toolcheck.pack_forget()
    label_cvesearch.pack(pady=20, side="top")
    cvesearch.pack(fill="both", expand=True)

    # Check if search bar and results frame already exist
    if hasattr(show_cvesearch_page, 'search_frame'):
        show_cvesearch_page.search_frame.pack()
    else:
        # Create search bar
        show_cvesearch_page.search_frame = tk.Frame(cvesearch, bg="light blue")
        show_cvesearch_page.search_frame.pack(side="top", fill="x")

        # Add search bar
        search_label = tk.Label(show_cvesearch_page.search_frame, text="Search:", font=button_font, bg="light blue")
        search_label.pack(side="left", padx=10)

        show_cvesearch_page.search_entry = tk.Entry(show_cvesearch_page.search_frame, font=button_font, width=30)
        show_cvesearch_page.search_entry.pack(side="left", padx=10)

        # Add sort by dropdown menu
        sort_label = tk.Label(show_cvesearch_page.search_frame, text="Sort by:", font=button_font, bg="light blue")
        sort_label.pack(side="left", padx=10)

        show_cvesearch_page.sort_var = tk.StringVar()
        sort_options = ["CveID", "Vendor", "Score", "Description"]
        sort_dropdown = tk.OptionMenu(show_cvesearch_page.search_frame, show_cvesearch_page.sort_var, *sort_options)
        sort_dropdown.pack(side="left", padx=10)

    if hasattr(show_cvesearch_page, 'results_frame'):
        show_cvesearch_page.results_frame.pack()
    else:
        # Create results frame
        show_cvesearch_page.results_frame = tk.Frame(cvesearch)
        show_cvesearch_page.results_frame.pack(fill="both", expand=True)

        # Create a Treeview widget to display the results
        show_cvesearch_page.results_tree = ttk.Treeview(show_cvesearch_page.results_frame, show="headings")

        # Create a horizontal scrollbar
        show_cvesearch_page.tree_x_scrollbar = ttk.Scrollbar(show_cvesearch_page.results_frame, orient="horizontal", command=show_cvesearch_page.results_tree.xview)

        # Configure the scrollbar and Treeview
        show_cvesearch_page.results_tree.configure(xscrollcommand=show_cvesearch_page.tree_x_scrollbar.set)
        show_cvesearch_page.results_tree.pack(fill="both", expand=True)
        show_cvesearch_page.tree_x_scrollbar.pack(side="bottom", fill="x")

    # File Path
    dir_path = os.path.dirname(os.path.realpath(__file__))
    csv_filename = 'CVECSV.csv'
    csv_file = os.path.join(dir_path, csv_filename)

    # Read the CSV file and update the data
    with open(csv_file, "r", encoding="utf-8") as file:
        reader = csv.reader(file)
        data = list(reader)

    display_csv_data(data) 

    def search_cve_wrapper():
        search_text = show_cvesearch_page.search_entry.get()
        sort_by = show_cvesearch_page.sort_var.get()
        search_cve(search_text, sort_by, show_cvesearch_page.results_tree)

    # # Create search button if it doesn't exist
    if not hasattr(show_cvesearch_page, 'search_button'):
        show_cvesearch_page.search_button = tk.Button(show_cvesearch_page.search_frame, text="Search", command=search_cve_wrapper, **button_style)
        show_cvesearch_page.search_button.pack(side=tk.LEFT, padx=10, pady=5)

        show_cvesearch_page.upload_button = tk.Button(show_cvesearch_page.search_frame, text="Upload", command=upload, **button_style)
        show_cvesearch_page.upload_button.pack(side=tk.LEFT,pady=5)

    # Forget and re-pack the search button to ensure it is displayed correctly
    show_cvesearch_page.search_button.pack_forget()
    show_cvesearch_page.search_button.pack(side=tk.LEFT, padx=10, pady=5)
    show_cvesearch_page.upload_button.pack_forget()
    show_cvesearch_page.upload_button.pack(side=tk.LEFT, pady=5)

def upload():
    file_paths = filedialog.askopenfilenames(filetypes=[("Word Documents", "*.docx"), ("Text Files", "*.txt")])
    rows_to_display = []  # create an empty list to store the results

    for file_path in file_paths:
        if file_path.endswith(".docx") or file_path.endswith(".txt"):
            # call the search_csv_by_id function and append the results to the list
            rows_to_display += search_csv_by_id(file_path, 'D:/SIT/Y1S3/INF1008/Project/output.csv')
        else:
            print("Invalid file format. Please upload a DOCX or TXT file.")

    # call the display_csv_data function with the accumulated results
    display_csv_data(rows_to_display)

def search_csv_by_id(file_path, csv_file):

    with open(file_path) as f:
        ids = f.read().splitlines() 

    # Read the CSV file and get the ID column
    df = pd.read_csv(csv_file)
    id_col = df['CveID']
    # Create a list to store the rows to display
    rows_to_display = []

    # Perform binary search on the IDs
    for id in ids:
        left, right = 0, len(id_col) - 1
        while left <= right:
            mid = (left + right) // 2
            if id_col[mid] == id:
                # ID found, add the row to the list
                row = df.loc[mid, :]
                rows_to_display.append(row)
                break
            elif id_col[mid] < id:
                left = mid + 1
            else:
                right = mid - 1

    return rows_to_display

def show_full_text(event):
    item = show_cvesearch_page.results_tree.selection()[0]
    description = show_cvesearch_page.results_tree.item(item, "values")[3]

    # Create a new window to display the full text
    full_text_window = tk.Toplevel()
    full_text_window.title("Full Description")
    full_text_label = tk.Label(full_text_window, text=description)
    full_text_label.pack()

def search_cve(search_text, sort_by=None, results_text=None):

    # Read in the CVE data from a CSV file
    cve_data = pd.read_csv("output.csv")

    # Convert search_text to lowercase
    search_text = search_text.lower()

    # Filter the data based on the search text
    filtered_data = cve_data[cve_data["CveID"].str.lower().str.contains(search_text)]

    # Sort the filtered data by the specified column
    if sort_by is not None:
        filtered_data = filtered_data.sort_values(by=sort_by, ascending=True)

    # Create a formatted string with the column headings and the data
    columns = filtered_data.columns.tolist()
    formatted_data = ""
    formatted_data += "{:<15}{:<20}{:<10}{:<50}\n".format(columns[0], columns[1], columns[2], columns[3])
    formatted_data += "=" * 95 + "\n"

    for index, row in filtered_data.iterrows():
        cve_id = row[columns[0]]
        vendor = row[columns[1]]
        score = row[columns[2]]
        description = row[columns[3]]
        formatted_data += "{:<15}{:<20}{:<10}{:<50}\n".format(cve_id, vendor, score, description)

    # Clear the Text widget before displaying the new search results
    results_text.delete(1.0, tk.END)

    # Display the filtered results in the Text widget
    results_text.insert(tk.END, filtered_data.to_string(index=False))


# Analysis Page
def show_analysis_page():
    print("Analysis Page Clicked")
    
    # # Restore the visibility of home_page, label_toolcheck, and label_cvesearch
    # home_page.pack()
    # label_toolcheck.pack()
    # label_cvesearch.pack()

    # Hide label_analysis and analysis widgets
    label_analysis.pack_forget()
    analysis.pack_forget()

    # Ask for number of items
    num_items = simpledialog.askinteger("Number of vendors", "Enter the number of vendors to display:")
    
    if num_items is None:
        return

    for child in page_frame.winfo_children():
        child.pack_forget()
    home_page.pack_forget()
    label_toolcheck.pack_forget()
    label_cvesearch.pack_forget()
    label_analysis.pack(pady=20, side="top")
    analysis.pack(fill="both", expand=True)

    if not bar_chart_created:
        create_bar_chart()
    else:
        # Clear bar chart data before replotting
        plt.clf()
        # Remove the bar chart from the frame
        bar_chart.get_tk_widget().pack_forget()
        

    # Repack the bar chart and existing label
    bar_chart.get_tk_widget().pack(fill='both', expand=True)
    label_analysis.pack(pady=20, side="top")

    print("Number items below:")
    print(num_items)
    vendor_frequency_analysis(num_items)
    
def show_home_page():
    toolcheck.pack_forget()
    cvesearch.pack_forget()
    analysis.pack_forget()
    home_page.pack(fill="both", expand=True)   

def create_bar_chart():
    global bar_chart_created, bar_chart

    if not bar_chart_created:
    # Data for the bar chart
        # CVEs = ['CVE-2020-1234', 'CVE-2021-1234', 'CVE-2022-1234']
        # values = [40, 20, 15]

        # # Create a bar chart
        # plt.bar(CVEs, values)
        # plt.xlabel('CVEs')
        # plt.ylabel('Values')
        # plt.title('Bar Chart for CVEs')

        # Display the bar chart
        fig = plt.gcf()  # Get the current figure
        bar_chart = FigureCanvasTkAgg(fig, master=analysis)
        bar_chart.draw()
        bar_chart.get_tk_widget().pack(fill='both', expand=True)
        bar_chart_created = True

# Create the Page 1
toolcheck = tk.Frame(page_frame, bg="light blue")
label_toolcheck = tk.Label(toolcheck, text="System Security Checker", font=title_font, bg="#f2f2f2")

# Create the Page 2
cvesearch = tk.Frame(page_frame, bg="light blue")
label_cvesearch = tk.Label(cvesearch, text="CVE Search", font=title_font, bg="#f2f2f2")


# Create the Page 3
analysis = tk.Frame(page_frame, bg="light blue")
label_analysis = tk.Label(analysis, text="Vendor Analysis", font=title_font, bg="#f2f2f2")

# Create navigation buttons
nav_frame = tk.Frame(root, bg="#f2f2f2")
nav_frame.pack(side="bottom", pady=10)

home_button = tk.Button(nav_frame, text="Home", command=show_home_page, **button_style)
home_button.pack(side="left", padx=10)

page1_button = tk.Button(nav_frame, text="System Security Checker", command=show_toolcheck_page, **button_style)
page1_button.pack(side="left", padx=10)


page2_button = tk.Button(nav_frame, text="CVE Search", command=show_cvesearch_page, **button_style)
page2_button.pack(side="left", padx=10)

page3_button = tk.Button(nav_frame, text="Vendor Analysis", command=show_analysis_page, **button_style)
page3_button.pack(side="left", padx=10)

root.geometry(f"{screen_width}x{screen_height}")  # Set window size to full screen

# Create a Frame for the return button
return_frame = tk.Frame(cvesearch, bg="light blue")
return_frame.pack(side="bottom", fill="x")
    
# Add the return button
return_button = tk.Button(return_frame, text="Return to Home", command=show_home_page, **button_style)
return_button.pack(pady=10)



# Set initial page
show_page(home_page)

def quit_program():
    root.quit()
    global is_program_running
    is_program_running = False
    root.destroy()

# Bind the on_close function to the close event of the GUI window
root.protocol("WM_DELETE_WINDOW", quit_program)

quit_button = tk.Button(nav_frame, text="Quit", command=quit_program, **button_style)
quit_button.pack(side="left", padx=10)


root.mainloop()