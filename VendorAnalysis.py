import matplotlib.pyplot as plt
import csv

#############################################################################################
#######################                                            ##########################
#######################     Vendor Frequency Analysis  for App     ##########################
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

def vendor_frequency_analysis(num_items):
    vendor_counts = {}

    # Opens CSV file to carry out frequency analysis on most frequent vendors
    with open('CVECSV.csv', 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            vendor = row['Vendor']
            # Do not show vendors with 'n/a' or empty fields
            if vendor != 'n/a' and vendor != '':
                if vendor in vendor_counts:
                    vendor_counts[vendor] += 1
                else:
                    vendor_counts[vendor] = 1

    sorted_vendors = list(vendor_counts.items())
    sorted_vendors = merge_sort(sorted_vendors)[::1]
    
    top_vendors = sorted_vendors[:num_items]  # Select number of vendors defined by user to display

    top_vendors = top_vendors[::-1]  # Reverse the list to show highest frequency at the top in the chart

    vendors = [vendor for vendor, count in top_vendors]
    frequencies = [count for vendor, count in top_vendors]

    plt.barh(vendors, frequencies)  # Create a horizontal bar chart

    # Display the frequency value beside each bar
    for i, freq in enumerate(frequencies):
        plt.text(freq, i, str(freq), va='center')

    plt.xlabel('Frequency')  # Label for the x-axis
    plt.ylabel('Vendor')  # Label for the y-axis
    plt.title("Top "+str(num_items)+" Vendors by Frequency")  # Title of the plot
    plt.tight_layout()  # Ensure labels fit within the plot
    # plt.show()  # Display the plot