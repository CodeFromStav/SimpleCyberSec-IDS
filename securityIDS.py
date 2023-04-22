import json
import pandas as pd

# Read the JSON log file
with open('/var/log/suricata/eve.json', 'r') as f:
    log_entries = [json.loads(line) for line in f]

# Load the data into a pandas DataFrame
df = pd.DataFrame(log_entries)

# Filter, analyze, or aggregate the data as needed
# For example, count the number of alerts by severity
alert_counts = df[df['event_type'] == 'alert']['severity'].value_counts()
print(alert_counts)
