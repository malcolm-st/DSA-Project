import tkinter as tk
# import tkinter.ttk as ttk
from tkinter import font, filedialog, messagebox, simpledialog, ttk, Scrollbar
import docx
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import csv
import win32api
import win32gui

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
from RetrieveCVE import *

# Global flag variable (for update)
is_program_running = True

# # Clone the repository to a local folder
# repo_url = "https://github.com/CVEProject/cvelistV5.git"
# local_folder = "scrapedCVE"

bar_chart_created = False
bar_chart = None
cache = {}



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

# Indefinitely check for updates
def check_for_updates():
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

def update():
    print("Update button clicked")

    # check_for_updates() will update CVEs properly, but GUI will not respond due to while loop
    # Use threading to call the function instead, run_update_checker()
    run_update_checker()

    # Testing updating csv file from .json updates file
    # update_csv_from_json()

# For retrieval
def retrieve_data():
    print("Retrieve Data button clicked")
    # Create a progress bar
    total_steps = 4
    progress_bar = tqdm(total=total_steps, unit="step")

    if not os.path.exists("scrapedCVE"):
        os.makedirs("scrapedCVE")

    # Retrieve CVEs from database
    pull_cves(progress_bar)
    # progress_bar.update(1)

    # Call the function to remove folders and files
    remove_folders_files(local_folder, progress_bar)
    # progress_bar.update(1)

    # Call the function to move files
    move_files("scrapedCVE/cves", "compiledCVE", progress_bar)

    # Removes original scrapedCVE folder
    shutil.rmtree("scrapedCVE")
    # progress_bar.update(1)

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

    # from RetrieveCVE import retrieve_data
    loading_thread = Thread(target=retrieve_data)
    loading_thread.start()

    check_retrieval_status()

def show_page(page):
    page.tkraise()

root = tk.Tk()
root.title("CVE Aggregator")

# Get the screen dimensions
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate the window position to appear right above the taskbar
taskbar_hwnd = win32gui.FindWindow("Shell_TrayWnd", None)
taskbar_rect = win32gui.GetWindowRect(taskbar_hwnd)
taskbar_height = taskbar_rect[1] - taskbar_rect[3]
window_x = 0
window_y = screen_height - (screen_height-taskbar_height)

# Set the window size and position using geometry()
root.geometry(f"{screen_width}x{screen_height-taskbar_height}+{window_x}+{window_y}")

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


#############################################################################################
#######################                                            ##########################
#######################        Show Toolcheck Page                 ##########################
#######################                                            ##########################
#############################################################################################

def show_toolcheck_page():
    print("Tool Page clicked")

    for child in page_frame.winfo_children():
        child.pack_forget()
    home_page.pack_forget()
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
def open_url(event):
    selected_row = show_cvesearch_page.results_tree.focus()
    cve_id = show_cvesearch_page.results_tree.item(selected_row)["values"][0]
    url = "https://nvd.nist.gov/vuln/detail/" + cve_id

    confirmed = messagebox.askyesno("Confirmation", "Are you sure you want to open the URL in a web browser?")
    if confirmed:
        webbrowser.open_new(url)

def display_csv_data(data, uploaded):
    # Clear existing data in Treeview
    show_cvesearch_page.results_tree.delete(*show_cvesearch_page.results_tree.get_children())

    header = ['CveID', 'Vendor', 'Score', 'Description']
    show_cvesearch_page.results_tree["columns"] = header

    # Configure column names and properties
    column_widths = [10, 10, 10, 400]  # Specify the width for each column
    column_min_widths = [100, 100, 100, 20000]  # Specify the minimum width for each column

    for i, col in enumerate(header):
        show_cvesearch_page.results_tree.heading(col, text=col, anchor=tk.W)
        show_cvesearch_page.results_tree.column(col, width=column_widths[i], minwidth=column_min_widths[i])

    # Populate the Treeview with data rows
    if uploaded == True:
        for row in data[0:]:
            show_cvesearch_page.results_tree.insert("", tk.END, values=row)
    else:
        for row in data[1:]:
            show_cvesearch_page.results_tree.insert("", tk.END, values=row)
    
    show_cvesearch_page.results_tree.bind("<Double-1>", open_url)


cvesearch = tk.Frame(page_frame, bg="light blue")

def show_cvesearch_page():
    # Clear previous contents of the page
    for child in page_frame.winfo_children():
        child.pack_forget()

    home_page.pack_forget()
    label_analysis.pack_forget()
    label_toolcheck.pack_forget()
    cvesearch.pack(fill="both", expand=True)

     # Check if search bar and results frame already exist
    if hasattr(show_cvesearch_page, 'search_frame'):
        show_cvesearch_page.search_frame.pack()
    else:
        label_cvesearch = tk.Label(cvesearch, text="CVE Search", font=title_font, bg="#f2f2f2")
        # Pack and lift the label_cvesearch widget
        label_cvesearch.pack(side="top", pady=20)
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
 
        # Create a vertical scrollbar
        show_cvesearch_page.tree_y_scrollbar = ttk.Scrollbar(show_cvesearch_page.results_frame, orient="vertical", command=show_cvesearch_page.results_tree.yview)

        # Create a horizontal scrollbar
        show_cvesearch_page.tree_x_scrollbar = ttk.Scrollbar(show_cvesearch_page.results_frame, orient="horizontal", command=show_cvesearch_page.results_tree.xview)

        # Configure the scrollbar and Treeview
        show_cvesearch_page.results_tree.configure(yscrollcommand=show_cvesearch_page.tree_y_scrollbar.set, xscrollcommand=show_cvesearch_page.tree_x_scrollbar.set)
        show_cvesearch_page.tree_y_scrollbar.pack(side="right", fill="y")

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

    display_csv_data(data, uploaded=False) 

    def search_cve_wrapper():
        search_text = show_cvesearch_page.search_entry.get()
        results = all_search(search_text, 'CVECSV.csv')
        display_csv_data(results, uploaded=False)

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

def all_search(search_query, csv_filename):
    # Check if search query exists in the cache
    if search_query in cache:
        print("Retrieving results from cache...")
        return cache[search_query]

    # Read CSV file and perform search
    data = pd.read_csv(csv_filename, encoding='utf-8')
    search_query = str(search_query).lower()
    filtered_data = data[data.apply(lambda row: any(search_query in str(cell).lower() for cell in row), axis=1)]
    results = filtered_data.values.tolist()

    # Cache the results
    cache[search_query] = results

    # Check cache size and clear if necessary
    if len(cache) > 100:
        print("Clearing cache...")
        cache.clear()

    return results

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
    display_csv_data(rows_to_display, uploaded=True)

def search_csv_by_id(file_path, csv_file):
    # Initialize an empty list to store the IDs
    ids = []
    
    # Check if the file path ends with .txt
    if file_path.endswith(".txt"):
        # Open the file in read mode
        with open(file_path) as f:
            # Read each line, strip it of leading/trailing whitespace, and add it to the list of IDs if it's not empty
            ids = [line.strip() for line in f if line.strip()]
    # Check if the file path ends with .docx
    elif file_path.endswith(".docx"):
        # Open the DOCX file using the docx library
        doc = docx.Document(file_path)
        # Iterate over each paragraph in the document
        for paragraph in doc.paragraphs:
            # Get the text of the paragraph, strip it of leading/trailing whitespace
            line = paragraph.text.strip()
            # If the line is not empty, add it to the list of IDs
            if line:
                ids.append(line)
    else:
        # If the file is not a TXT or DOCX file, print an error message and return an empty list
        print("Invalid file format. Please upload a DOCX or TXT file.")
        return []
    
    # Open the CSV file in read mode with utf-8 encoding
    with open(csv_file, "r", encoding="utf-8") as file:
        # Create a CSV reader object to read the contents of the file
        reader = csv.reader(file)
        
        header = next(reader)
        
        cve_id_index = header.index('CveID')
        
        data = {row[cve_id_index]: row for row in reader}

    # Initialize an empty list to store the rows to display
    rows_to_display = []
    
    # Initialize an empty set to store unique CVE IDs (to avoid displaying duplicate rows)
    unique_cve_ids = set()
    
    # Iterate over each ID in the list of IDs
    for cve_id in ids:
        # Check if the ID is in the data dictionary and has not already been added to the unique_cve_ids set
        if cve_id in data and cve_id not in unique_cve_ids:
            # Add the row corresponding to that ID to the rows_to_display list
            rows_to_display.append(data[cve_id])
            # Add the ID to the unique_cve_ids set
            unique_cve_ids.add(cve_id)

    # Check if no rows were found or if the last row added does not match the last ID searched for
    if not rows_to_display or rows_to_display[-1][cve_id_index] != cve_id:
        # Print a message indicating that no results were found for that ID
        print(f"No results found for {cve_id}")

    # Return the list of rows to display
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
    cve_data = pd.read_csv("CVECSV.csv")

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
    
# Add the Reset button
return_button = tk.Button(return_frame, text="Reset Filters", command=show_cvesearch_page, **button_style)
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
