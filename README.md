# umbrellaGrepScript
Pulls domains from Umbrella via API, specified by content or security category ID.
Finds instances of those domains in Windows DNS Logs, returning the source IP reaching out to said domain.

Usage:

python umbrellaGrepScript.py [-h] [-v, --verbose] [-c, --category] [-o OUTFILE] dnsLog apiKey apiSecret clientID dateToSearch

dnsLog: Windows DNS Log to use for parsing. MAKE SURE "DETAILED" IS DISABLED IN DNS DEBUGGING.
apiKey: Umbrella API key for the organization.
apiSecret: Umbrella API secret for the organization.
clientID: Umbrella organizational/client ID for the organization.
dateToSearch: Integer, how far back to search for traffic in Umbrella. EX: 30 (for 30 days to now)
-v, --verbose: Boolean (true, false), prints each line of DNS Log along with current domain as it searches.
-c, --category: Integer, content or security category ID from Umbrella. Allows user to specify what traffic they want to grab from Umbrella. CNC is default (65).
-o: Log all command output to a specified file.


https://github.com/trippedego/umbrellaGrepScript
