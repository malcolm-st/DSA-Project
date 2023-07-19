import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


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

# The function will create the chart
def create_year_chart(year):
    # Check if the chart attribute exists in the year frame
    chart_attribute_exists = hasattr(year, "chart")

    if chart_attribute_exists:
        # If the attribute exists, remove the previous chart
        year.chart.get_tk_widget().pack_forget()
    else:
        # If the attribute doesn't exist, create it
        year.chart = None

    # Load the CSV file into a pandas DataFrame
    df = pd.read_csv('CVECSV.csv')

    # Extract the year from the CVE ID
    df['Year'] = df['CveID'].str.extract(r'CVE-(\d{4})-\d+')

    # Count the number of CVEs for each year
    year_counts = df['Year'].value_counts()

    # Sort the years in ascending order based on the number of CVEs
    sorted_years = dict(sorted(year_counts.items(), key=lambda x: x[1]))

    # Extract the top five years with the most CVEs
    top_five_years = dict(list(sorted_years.items())[-5:])

    # Create a bar chart of the top five years with the most CVEs
    fig, ax = plt.subplots()
    ax.bar(top_five_years.keys(), top_five_years.values())
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('Top Five Years with the Most CVEs')

    # Embed the Matplotlib graph in the Year Page
    canvas = FigureCanvasTkAgg(fig, master=year)
    canvas.draw()
    canvas.get_tk_widget().pack()

    # Assign the chart attribute in the year frame
    year.chart = canvas