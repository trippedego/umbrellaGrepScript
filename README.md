# umbrellaGrepScript
Pulls domains from Umbrella via API, specified by content or security category ID.  
Finds instances of those domains in Windows or Bind9 DNS Logs, returning the source IPs reaching out to said domain with timestamps.  

Usage:  
  
python umbrellaGrepScript.py [-h] [-s, --smb HOSTNAME IP USERNAME PASSWORD SHARE PATHTOFILE] [-w, --windows] [-b, --bind] [-v, --verbose] [-c, --category] [-o OUTFILE] dnsLog apiKey apiSecret clientID dateToSearch  
  
dnsLog: DNS Log (Windows or Bind9) to use for parsing. MAKE SURE "DETAILED" IS DISABLED IN WINDOWS DNS DEBUGGING.  
apiKey: Umbrella API key for the organization.  
apiSecret: Umbrella API secret for the organization.  
clientID: Umbrella organizational/client ID for the organization.  
dateToSearch: Integer, how far back to search for traffic in Umbrella. EX: 30 (for 30 days to now)  
-s HOSTNAME IP USERNAME PASSWORD SHARE FILE, --smb HOSTNAME IP USERNAME PASSWORD SHARE FILE  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;OPTIONAL: Grab Windows DNS Log via SMB. Use: --smb "Server Hostname" "Server IP" "Username" "Password" "Share" "Path to DNS Log"  
-w, --windows: Parse a Windows DNS Log.  
-b, --bind: Parse a Bind9 DNS Log.  
-v, --verbose: Prints each line of DNS Log along with current domain as it searches.  
-c, --category: Integer, content or security category ID from Umbrella. Allows user to specify what traffic they want to grab from Umbrella. CNC is default (65).  
-o: Log all command output to a specified file.  

Written by Peter Kotsiris in Python 3.8.5  
https://github.com/trippedego/umbrellaGrepScript


![alt text]https://github.com/trippedego/umbrellaGrepScript/blob/main/images/help.png)
