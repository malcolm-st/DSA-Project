import csv
import matplotlib.pyplot as plt
import re


#############################################################################################
#######################                                            ##########################
#######################             Year Analysis for App          ##########################
#######################                                            ##########################
#############################################################################################

def merge_sort(arr):
    if len(arr) <= 1:
        return arr

    mid = len(arr) // 2
    left = arr[:mid]
    right = arr[mid:]

    left = merge_sort(left)
    right = merge_sort(right)

    return merge(left, right)

def merge(left, right):
    merged = []
    i = j = 0

    while i < len(left) and j < len(right):
        if left[i][1] > right[j][1]:
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1

    merged.extend(left[i:])
    merged.extend(right[j:])

    return merged

# Used to gather the Year of the CVEs using regex
def sanitize_cve_id(cve_id):
    # Use regular expression to extract the year from the CVE ID
    year_match = re.search(r'CVE-(\d{4})-\d+', cve_id)
    if year_match:
        return year_match.group(1)
    else:
        return 'n/a' 

# Used to plot the chart for CVE Year Analysis
def year_frequency_analysis(num_year):
    years = {}  # Clear the years dictionary

    # Opens CSV file to carry out frequency analysis on CVEs by year
    with open('CVECSV.csv', 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            cve_id = row['CveID']
            year = sanitize_cve_id(cve_id)
            # Do not consider years with 'n/a' or empty fields
            if year != 'n/a' and year != '':
                if year in years:
                    years[year] += 1
                else:
                    years[year] = 1

    sorted_years = sorted(years.items(), key=lambda x: x[1], reverse=True)
    top_years = sorted_years[:num_year]  # Select number of years defined by user to display

    years_labels = [year for year, count in top_years]
    cve_counts = [count for year, count in top_years]

    plt.barh(years_labels, cve_counts)  # Create a bar chart

    # Display the frequency value above each bar
    for i, freq in enumerate(cve_counts):
        plt.text(freq, i, str(freq), va='center')

    plt.xlabel('Number of CVEs')  # Label for the x-axis
    plt.ylabel('Year')  # Label for the y-axis
    plt.title("Top " + str(num_year) + " Years with the Most CVEs")  # Title of the plot
    plt.tight_layout()  # Ensure labels fit within the plot