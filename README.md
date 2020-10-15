# umbrellaGrepScript
A python script to grab specific data from Cisco Umbrella via API and search for those domains in a Windows DNS Log to find suspicious source IPs.

Usage:

python umbrellaGrepScript dnsLog apiKey apiSecret clientID howFarToSearchInUmbrella --outfile file

umbrellaGrepScript.py [-h] [-o OUTFILE] dnsLog apiKey apiSecret clientID dateToSearch
                  
Positional Arguments:
  dnsLog                Windows DNS Log to parse
  apiKey                Umbrella Reporting API Key
  apiSecret             Umbrella Reporting API Secret
  clientID              Umbrella Client ID for Organization
  dateToSearch          How far back you want to look for logs in Umbrella,
                        from 1 day to 30 days. EX: 30 (for 30 days)

Optional Arguments:
  -h, --help            show this help message and exit
  -o OUTFILE, --outFile OUTFILE
                        Name of file to save command output to.

https://github.com/trippedego/umbrellaGrepScript
