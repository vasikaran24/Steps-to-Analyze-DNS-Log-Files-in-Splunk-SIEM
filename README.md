# Steps-to-Analyze-DNS-Log-Files-in-Splunk-SIEM

1. Search for DNS Events
-------------------------

Open Splunk interface and navigate to the search bar.
Enter the following search query to retrieve DNS events

    index=* sourcetype=dns_sample


2. Extract Relevant Fields
---------------------------

Identify key fields in DNS logs such as source IP, destination IP, domain name, query type, response code, etc.
As mentioned below, | regex _raw=”(?i)\b(dns|domain|query|response|port 53)\b”: This regex searches for common DNS-related keywords in the raw event data.

    index=* sourcetype=dns_sample | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b"


 3. Identify Anomalies
-----------------------

Look for unusual patterns or anomalies in DNS activity.
query to identify spikes

    index=_* OR index=* sourcetype=dns_sample  | stats count by fqdm

    
4. Find the top DNS sources
---------------------------

Use the top command to count the occurrences of each query type:

    index=* sourcetype=dns_sample | top fqdn, src_ip

5. Investigate Suspicious Domains
---------------------------------

Search for domains associated with known malicious activity or suspicious behavior.
Utilize threat intelligence feeds or reputation databases to identify malicious domains such virustotal.com
search for known malicious domains:

    index=* sourcetype=dns_sample fqdn="maliciousdomain.com"
    

   







