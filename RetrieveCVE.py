import git
import os
import subprocess
import shutil
import csv
import time
import json

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