import requests
from bs4 import BeautifulSoup
import zipfile
import io
import time
import threading
import os
import shutil
import json
import csv
# from GUIFORDSA import is_program_running

#############################################################################################
#######################                                            ##########################
#######################             Update CVE for App             ##########################
#######################                                            ##########################
#############################################################################################

def move_files_update(source_directory, destination_directory):
    # if not os.path.exists("testmove"):
    #     os.makedirs("testmove")

    # Iterate over all items in the source directory
    for item in os.listdir(source_directory):
        item_path = os.path.join(source_directory, item)
        # Check if the item is a file
        if os.path.isfile(item_path):
            # Remove the existing file in the destination directory if it exists
            destination_path = os.path.join(destination_directory, item)
            if os.path.exists(destination_path):
                os.remove(destination_path)
            # Move the file to the destination directory
            shutil.move(item_path, destination_directory)
        # Check if the item is a directory
        elif os.path.isdir(item_path):
            # Recursively move files in the sub-directory
            move_files_update(item_path, destination_directory)

def update_csv_from_json():
    json_folder = 'updatedCVE/deltaCves'
    csv_file = 'CVECSV.csv'

    csv_data = []  # List to store the CSV data

    # Check if the CSV file exists
    csv_exists = os.path.exists(csv_file)

    # Read existing CSV data if the file exists
    if csv_exists:
        with open(csv_file, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            csv_data = list(reader)

    # Check if the last row is the header row only
    last_row_header_only = csv_exists and csv_data and csv_data[0][0] == 'CveID'

    for filename in os.listdir(json_folder):
        if filename.endswith('.json'):
            cve_id = filename.split('.')[0]
            json_file = os.path.join(json_folder, filename)

            with open(json_file, 'r', encoding='utf-8') as json_data:
                data = json.load(json_data)

            # Access affected vendors
            affected_vendors = data.get('containers', {}).get('cna', {}).get('affected', [])
            vendor = affected_vendors[0].get('vendor', '') if affected_vendors else ''

            # Access base score
            metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
            score = metrics[0].get('cvssV3_0', {}).get('baseScore', '') if metrics else ''

            # Access description value
            descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''

            # Check if CveID already exists in CSV data
            cve_exists = False
            for row in csv_data:
                if row[0] == cve_id:
                    row[1] = vendor
                    row[2] = score
                    row[3] = description
                    cve_exists = True
                    break

            # If CveID doesn't exist, create a new row
            if not cve_exists:
                new_row = [cve_id, vendor, score, description]
                csv_data.append(new_row)

    # Add headers at the top of the CSV data if necessary
    if not last_row_header_only:
        csv_data.insert(0, ['CveID', 'Vendor', 'Score', 'Description'])

    # Write the updated CSV data back to the file
    with open(csv_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerows(csv_data)

def update_cve():
    # Define the URL and CSS selector
    url = "https://github.com/CVEProject/cvelistV5/releases"
    selector = "#repo-content-pjax-container > div > div:nth-child(3) > section:nth-child(1) > div > div.col-md-9 > div > div.Box-body > div.d-flex.flex-md-row.flex-column > div.d-flex.flex-row.flex-1.mb-3.wb-break-word > div.flex-1 > span > a"

    # Send a GET request to the URL
    response = requests.get(url)

    # Parse the HTML content with BeautifulSoup
    soup = BeautifulSoup(response.content, "html.parser")

    # Find the element that matches the selector and get the href attribute
    element = soup.select_one(selector)
    if element is not None:
        href = element.get("href")
        # print(href)
    else:
        print(f"No element found for CSS selector: {selector}")

    # Splicing of href attribute to create download link to download updated CVEs in .zip file
    spliced_output = href[35:]
    # print(spliced_output)

    year = spliced_output[4:8]
    # print(year)

    month = spliced_output[9:11]
    # print(month)

    day = spliced_output[12:14]
    # print(day)

    timeStamp = spliced_output[-5:]
    # print(timeStamp)

    downloadLink = "https://github.com/CVEProject/cvelistV5/releases/download/" + spliced_output + "/" + year + "-" + month + "-" + day + "_delta_CVEs_at_" + timeStamp + ".zip"
    # print(downloadLink)

    fileName = year + "-" + month + "-" + day + "_delta_CVEs_at_" + timeStamp + ".zip"
    # print(fileName)

    # Send a GET request to the URL and get the ZIP file content
    response = requests.get(downloadLink)
    zip_content = io.BytesIO(response.content)

    if not os.path.exists("updatedCVE"):
        os.makedirs("updatedCVE")

    # Extract the contents of the ZIP file to a directory
    with zipfile.ZipFile(zip_content, "r") as zip_ref:
        zip_ref.extractall("updatedCVE")

    # Update CVECSV.csv file
    update_csv_from_json()

    # Update compiledCVE folder
    # Overwrites updated CVE files into compiledCVE folder
    move_files_update("updatedCVE/deltaCves", "compiledCVE")

    # Removes original updatedCVE folder
    shutil.rmtree("updatedCVE")

# Indefinitely check for updates
def check_for_updates():
    from GUIFORDSA import is_program_running
    # Define the repository details
    username = "CVEProject"
    repository = "cvelistV5"
    branch = "main"

    # Define the API endpoint and headers
    api_endpoint = f"https://api.github.com/repos/{username}/{repository}/branches/{branch}"
    headers = {"Accept": "application/vnd.github.v3+json",
               "Authorization": "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"}

    # Initialize the last commit hash
    last_commit_hash = None

    # Loop indefinitely to check for updates
    while is_program_running:
        # Send a GET request to the API endpoint to get branch details
        response = requests.get(api_endpoint, headers=headers)

        # Check if the response is successful
        if response.ok:
            # Get the latest commit hash
            commit_hash = response.json()["commit"]["sha"]

            print("Checking Repo for commit hash")

            # Check if this is the first loop or if the commit hash has changed
            if last_commit_hash is None or commit_hash != last_commit_hash:
                print("Updating Local Database")
                # Update the local folder
                update_cve()

                # Update the last commit hash
                last_commit_hash = commit_hash

                # Log the update
                print(f"Updated local folder withnew changes from GitHub repository. Commit hash: {commit_hash}")

        else:
            # Log the error
            print(f"Error checking for updates: {response.status_code} {response.reason}")

        # Wait for 1 hour before checking again
        # time.sleep(3600)

        # Updates Database every minute
        time.sleep(60)

# Function to call the check_for_updates function in a separate thread so GUI will not crash
def run_update_checker():
    thread = threading.Thread(target=check_for_updates)
    thread.start()

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