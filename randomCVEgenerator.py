import csv
import random 

# Main dataset file path
csv_file = "CVECSV.csv" 
noOfCVEID = int(input("Enter number of randomly generated cve id:"))

# Open dataset file and randomly select 'user inputted' number of CVE ID
with open(csv_file, "r", encoding="utf-8") as csv_in:

    reader = csv.reader(csv_in)

    header = next(reader)
    cve_id_index = header.index('CveID')

    cve_ids = set([row[cve_id_index] for row in reader])

    # Convert set to list
    cve_id_list = list(cve_ids)  

    # Sample from list instead  
    random_cves = random.sample(cve_id_list, noOfCVEID)

# Request output file path from user 
output_path = input("Enter path for output text file: ")
output_file = output_path + "/test"+str(noOfCVEID)+".txt"

# Open CSV file and populate the generated CVE ID into it
with open(output_file, "w") as txt_out:
    for cve_id in random_cves:
        txt_out.write(cve_id + "\n")