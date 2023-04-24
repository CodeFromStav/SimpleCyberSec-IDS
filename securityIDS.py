import json
import pandas as pd

# Read the JSON log file
with open('/var/log/suricata/eve.json', 'r') as file_iter:
    log_entries = [json.loads(line) for line in file_iter]

# Load the data into a pandas DataFrame
df = pd.DataFrame(log_entries)

# Filter, analyze, or aggregate the data as needed
# For example, count the number of alerts by severity
# print(df.columns)
alert_counts, alert_counts2 = df[df['event_type'] == 'dhcp']['src_port'].value_counts(), df[df['event_type'] == 'dhcp']['src_ip'].value_counts()

print("Alert Counts:\n" + str(alert_counts) + str(alert_counts2))
