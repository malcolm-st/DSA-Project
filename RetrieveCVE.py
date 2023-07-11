# retrieve imports
import git
import os
import subprocess
import shutil
import csv
import time
import json
from tqdm import tqdm
# import tkinter as tk
# from tkinter import ttk
import threading
# from GUIFORDSA import retrieval_complete

#############################################################################################
#######################                                            ##########################
#######################            Retrieve CVE for App            ##########################
#######################                                            ##########################
#############################################################################################

# Clone the repository to a local folder
repo_url = "https://github.com/CVEProject/cvelistV5.git"
local_folder = "scrapedCVE"


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

# def check_retrieval_status():
#     if retrieval_complete.get():
#         # Show success message
#         success_label.config(text="Retrieve Data Successful")
#         # Destroy the loading window
#         loading_window.destroy()
#     else:
#         # Continue checking the status after 100ms
#         root.after(100, check_retrieval_status)

# def open_loading_window():
#     global loading_window, success_label, retrieval_complete
#     loading_window = tk.Toplevel(root)
#     loading_window.title("Loading...")
#     loading_window.geometry("400x100")
#     loading_window.resizable(False, False)

#     progress_label = ttk.Label(loading_window, text="Retrieving data...")
#     progress_label.pack(pady=10)

#     progress_bar = ttk.Progressbar(loading_window, mode="indeterminate", length=350)
#     progress_bar.pack(pady=10)
#     progress_bar.start()

#     success_label = ttk.Label(loading_window, text="")
#     success_label.pack(pady=10)

#     retrieval_complete = tk.BooleanVar()
#     retrieval_complete.set(False)

#     loading_thread = Thread(target=retrieve_data)
#     loading_thread.start()

#     check_retrieval_status()

# def retrieve_data():
#     print("Retrieve Data button clicked")
#     # Create a progress bar
#     total_steps = 4
#     progress_bar = tqdm(total=total_steps, unit="step")

#     if not os.path.exists("scrapedCVE"):
#         os.makedirs("scrapedCVE")

#     # Retrieve CVEs from database
#     # pull_cves(progress_bar)
#     progress_bar.update(1)

#     # Call the function to remove folders and files
#     # remove_folders_files(local_folder, progress_bar)
#     progress_bar.update(1)

#     # Call the function to move files
#     # move_files("scrapedCVE/cves", "compiledCVE", progress_bar)

#     # Removes original scrapedCVE folder
#     # shutil.rmtree("scrapedCVE")
#     progress_bar.update(1)

#     # # Convert .json files into a single CVECSV.csv files
#     # # Provide the folder containing JSON files and the desired CSV file
#     # dir_path = os.path.dirname(os.path.realpath(__file__))
#     # json_filename = 'compiledCVE'
#     # csv_filename = 'CVECSV.csv'
#     # json_folder = os.path.join(dir_path, json_filename)
#     # csv_file = os.path.join(dir_path, csv_filename)

#     # json_to_csv(json_folder, csv_file)

#     progress_bar.update(1)

#     # Close the progress bar
#     progress_bar.close()

#     # Signal that the retrieval process is complete
#     retrieval_complete.set(True)

def json_to_csv(json_folder, csv_file):
    # List all JSON files in the folder
    json_files = [file for file in os.listdir(json_folder) if file.endswith('.json')]

    with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        # Write header
        writer.writerow(['CveID', 'Vendor', 'Score', 'Description'])

        # Start the timer
        start_time =  time.time()
        # Process each JSON file
        for json_file in json_files:
            with open(os.path.join(json_folder, json_file), encoding='utf-8') as file:
                try:
                    data = json.load(file)
                    cve_id = data.get('cveMetadata', {}).get('cveId', '')
                    
                    # Access affected vendors
                    affected_vendors = data.get('containers', {}).get('cna', {}).get('affected', [])
                    vendor = affected_vendors[0].get('vendor', '') if affected_vendors else ''
                    
                    # Access base score
                    metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
                    score = metrics[0].get('cvssV3_0', {}).get('baseScore', '') if metrics else ''
                    
                    # Access description value
                    descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    writer.writerow([cve_id, vendor, score, description])
                except:
                    print(f"Error has occurred while processing {json_file}. Skipping the file.")
    
    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    print(f"Data extraction complete. Elapsed time: {elapsed_time:.2f} seconds.")