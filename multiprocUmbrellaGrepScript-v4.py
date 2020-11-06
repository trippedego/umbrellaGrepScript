import argparse
import time 
import re
import os
import requests
import json
import base64
import sys
import subprocess
import multiprocessing
from smb import SMBConnection

# Parser to grab arguments from the user.
parser = argparse.ArgumentParser()
parser.add_argument("apiKey", type=str, help="Umbrella Reporting API Key")
parser.add_argument("apiSecret", type=str, help="Umbrella Reporting API Secret")
parser.add_argument("clientID", type=str, help="Umbrella Client ID for Organization")
parser.add_argument("-l", "--dnsLog", type=str, help="DNS Log to parse. Only if --SMB is not used.")
parser.add_argument("-d", "--dateToSearch", type=str, help="How far back to look for logs in Umbrella, from 1 day to 30 days. Default = 1")
parser.add_argument("-s", "--smb", type=str, nargs=6, help='OPTIONAL: Grab Windows DNS Log via SMB. Use: --smb "Server Hostname" "Server IP" "Username" "Password" "Share" "PathToLogfile"')
parser.add_argument("-p", "--processes", type=int,  help="Number of processes for splitting the load of parsing. WINDOWS DNS LOG ONLY.")
parser.add_argument("-w", "--windows", action='store_true',  help="Parse a Windows DNS log.")
parser.add_argument("-b", "--bind", action='store_true',  help="Parse a Bind9 DNS log.")
parser.add_argument("-o", "--outFile", type=str, help="Name of file to save command output to.")
parser.add_argument("-c", "--category", type=str, help="Traffic category ID to grab from Umbrella. Command and Control (65) is Default.")
parser.add_argument("-v", "--verbose", action='store_true', help="Print verbose output.")
args = parser.parse_args()

def getAuth(apiKeyArg, apiSecretArg):
    '''
    getAuth(apiKeyArg: str, apiSecretArg: str) -> onlyAuth: str
    Get oAuth token from Umbrella, used for API v2.
    API v2 is needed to grab specific data from Umbrella, such as filtering categories. 
    '''

    message = apiKeyArg + ":" + apiSecretArg
    apiToken = (base64.b64encode(message.encode('ascii')))
    apiToken = str(apiToken)
    apiToken = apiToken[2:-1]

    authURL = "https://management.api.umbrella.com/auth/v2/oauth2/token"

    authHeaders = {
        "accept": "application/json",
        "Authorization": "Basic {}".format(apiToken)
    }

    response = requests.request("GET", authURL, headers=authHeaders)
    onlyAuth = ''
    # Split the response by comma, and find the line that starts with access_token. 
    # Grab only the oAuth token, removing any other characters.
    cleanedResponse = response.text.split(",")
    for line in cleanedResponse:
        if (line.find("access_token") != -1):
            tempLine = line[16::]
            onlyAuth = tempLine[:-1]
            
    
    return onlyAuth

def getUmbrellaLogs(clientIDArg, oAuthToken, umbrellaDate):
    '''
    getUmbrellaLogs(clientIDArg: str, oAuthToken: str, umbrellaDate: int) -> response.text: str
    Using the oAuth token and Umbrella Organization ClientID, grab traffic with specified parameters
    such as how far back to search in Umbrella and category ID (CNC, 65 is default). This will grab
    the last 500 logs which is the max available to grab via API. It will return full Umbrella logs
    which we will then filter to only have domains in formatDomains().
    '''
    domainURL = "https://reports.api.umbrella.com/v2/organizations/{}/activity".format(clientIDArg)

    if umbrellaDate:
        formattedDate = "-{}days".format(str(umbrellaDate))
    else:
        formattedDate = "-1days"

    if args.category:
        categoryID = str(args.category)
        domainPayload = {"from":formattedDate,"to":"now","limit":"500","categories":categoryID}
    else:
        domainPayload = {"from":formattedDate,"to":"now","limit":"500","categories":"65"}

    domainHeaders = {
        "accept": "application/json",
        "authorization": "Bearer {}".format(oAuthToken)
    }

    response = requests.request("GET", domainURL, headers=domainHeaders, params=domainPayload)
    return response.text

def formatDomains(umbrellaLogs):
    '''
    formatDomains(umbrellaLogs: str) -> badDomains: list
    Split the Umbrella Logs by commas, find each domain, and store it into a set so all domains are 
    unique. Cast that set to a list so we can iterate easily over it.
    '''
    allLines = umbrellaLogs.split(",")
    badDomains = list()
    print("\nDomains grabbed from Umbrella:\n")
    for line in allLines:
        if (line.find("domain") != -1):
            # Uncleaned domain: "domain":"api.wipmania.com"
            # Remove the first 10 characters to get: api.wipmania.com"
            # Finally remove the last character to get the cleaned domain: api.wipmania.com
            tempLine = line[10::]
            cleanedDomain = tempLine[:-1]
            # Append the cleanedDomain to badDomains but strip the newline at the end.
            badDomains.append(cleanedDomain.rstrip())

    # Cast badDomains to a set, in order to unique all values, then into a list for easy iteration.
    badDomains = list(set(badDomains))

    for domain in badDomains:
        print(domain)
    print("\n")
    
    return badDomains

def parseBindLog(badDomains, timestamp):
    '''
    parseBindLog(badDomains: list) -> void
    Parse through the Bind DNS log for instances of bad domains, printing to stdout and writing to file,
    badDomains.txt, both the source IP and domain visited with a timestamp.
    '''
    # Open the Bind DNS log, store each line in a list, removing new line and return.
    log = open(args.dnsLog, "r").read().split("\n")

    # Open a new file for writing, badDomains-*timestamp*.txt in user's current working directory.
    fileName = "badDomains-{}.txt".format(timestamp)
    fileBadDomains = open(fileName, "w")

    # Sort both the DNS log and domains for better efficiency.
    log.sort()
    badDomains.sort()

    # Create a set for findings so all duplicates are removed.
    findings = set()

    # Iterate through each line of the log, storing each word into a list, grab the IP and record from the line.
    for line in log:
        splitCurrLine = line.split(" ")
        
        try:
            currRecord = splitCurrLine[7].strip("):").strip("(")
        except:
            continue
        currIP = splitCurrLine[6].split("#")[0]
        
        
        # Iterate through each record in badDomains
        for record in badDomains:
            
            # If user wants verbosity, print every operation, each record being found in each line of the DNS log.
            if (args.verbose):
                print("Finding {} in {}".format(record, line))
                if record == currRecord:
                    if line.find("208.67.220.220") != -1 or line.find("208.67.222.222") != -1 or line.find("127.0.0.1") != -1:
                        continue
                    else:
                        print("{} reached out to {} on {} {} at {}\n".format(currIP, currRecord,splitCurrLine[0], splitCurrLine[1], splitCurrLine[2]))
                        findings.add("{} reached out to {} on {} {} at {}\n".format(currIP, currRecord,splitCurrLine[0], splitCurrLine[1], splitCurrLine[2]))

            # See if any of the bad domains are in the line, if they are then add them to findings and print to stdout.
            elif record == currRecord:
                if line.find("208.67.220.220") != -1 or line.find("208.67.222.222") != -1 or line.find("127.0.0.1") != -1:
                    continue
                else:
                    print("{} reached out to {} on {} {} at {}\n".format(currIP, currRecord,splitCurrLine[0], splitCurrLine[1], splitCurrLine[2]))
                    findings.add("{} reached out to {} on {} {} at {}\n".format(currIP, currRecord,splitCurrLine[0], splitCurrLine[1], splitCurrLine[2]))

    # Cast findings to a list for easy iteration.
    findings = list(findings)

    # Write each entry in findings to badDomains-*timestamp*.txt
    for entry in findings:
        fileBadDomains.write(entry)
    fileBadDomains.close()

def getFiles(hostname, ip, username, password, share, path):
    conn = SMBConnection(username,
                        password,
                        ip,
                        hostname,
                        use_ntlm_v2 = True)

    assert conn.connect(ip, 139)

    with open(hostname+'.log', 'wb') as fp:
        conn.retrieveFile(share, path, fp)

def parseWindowsLog(badDomains, timestamp, return_dict, count):
    '''
    parseWindowsLog(badDomains: list) -> void
    Parse through the Windows DNS log for instances of bad domains, printing to stdout and writing to file,
    badDomains.txt, both the source IP and domain visited with a timestamp.
    '''

    # Open the Windows DNS log, store each line in a list, removing new line and return
      
    if args.smb:
        # Open DNS Log that has been grabbed via SMB.
        log = open(args.smb[0]+".log", "r").read().split("(0)")
    else:
        # Open DNS Log if it has not been grabbed by SMB.
        log = open(args.dnsLog, "r").read().split("(0)")
    
    
    # Sort both the DNS log and domains for better efficiency.
    log.sort()
    badDomains.sort()

    # Create a set for findings so all duplicates are removed.
    findings = set()
    
    # Start to parse through DNS log.
    for line in log:

        # If the current line contains nothing, continue to next line of DNS log.
        if line == '':
            continue
        
        # Split the current line of the DNS log by spaces, and store the list of each element.
        line.rstrip()
        splitCurrLine = line.split(' ')
        
        try:
            # The IP in each line of the log is stored in the ninth index.
            # If there is no ninth index, which is the case for the log header and detailed logs,
            # continue to next line.
            currentIP = splitCurrLine[9]
        except:
            continue
        
        # The current DNS record is the last index in the line, store that in currRecord.
        # Right now, the currRecord looks like: (5)debug(7)opendns(3)com(0)
        # We will need to do some regex to remove the parentheses and put periods where they should be.
        currRecord = splitCurrLine[-1]
        
        # Some regex to remove the parentheses from currRecord.
        splitRERecord = re.split("\(\d+\)",currRecord)
        fixedDNSRecord= ""
        tempRE = ""

        # At this point, splitRERecord looks like: ['', 'debug', 'opendns', 'com', '']
        # This will format it to look like: debug.opendns.com.. (extra periods at the end)
        for word in splitRERecord:
            if word == "":
                continue
            fixedDNSRecord += word
            tempRE += fixedDNSRecord + "."
            fixedDNSRecord= ""
        
        splitRE = tempRE.split(".")
        valRE = ""

        for valIndex in range(len(splitRE)):
            valRE += splitRE[valIndex] + "."
        
        # This will cut off the last two characters (periods) so the final result looks like: debug.opendns.com
        currRecord=(valRE[0:-2])
        
        splitDomain = list()

        # This is also for filtering out bad lines/records in the DNS log.
        for currRecord in badDomains:
            try:
                splitDomain = splitRE[-3].find(currRecord)
            except:
                continue
            
            splitDomain = currRecord.split('.')

            # If user wants verbosity, print every operation, each record being found in each line of the DNS log.
            if (args.verbose):
                print("Finding {} in {}".format(currRecord, line))
                if splitRE[-3].find(splitDomain[-2]) != -1:
                    if line.find("208.67.220.220") != -1 or line.find("208.67.222.222") != -1 or line.find("127.0.0.1") != -1:
                        continue
                    else:
                        # print("{} reached out to {} on {} at {}{}\n".format(currentIP,currRecord,splitCurrLine[0][2::],splitCurrLine[1],splitCurrLine[2]))
                        findings.add("{} reached out to {} on {} at {}{}\n".format(currentIP,currRecord,splitCurrLine[0][2::],splitCurrLine[1],splitCurrLine[2]))
            
            # Finally, if the badDomain is in the line of the DNS log, print to stdout and store the source IP, badDomain, and timestamp into findings.
            # Unless, the source IP is one of Umbrellas DNS servers or localhost.
            elif splitRE[-3].find(splitDomain[-2]) != -1:
                if line.find("208.67.220.220") != -1 or line.find("208.67.222.222") != -1 or line.find("127.0.0.1") != -1:
                    continue
                else:
                    #print("{} reached out to {} on {} at {}{}\n".format(currentIP,currRecord,splitCurrLine[0][2::],splitCurrLine[1],splitCurrLine[2]))
                    findings.add("{} reached out to {} on {} at {}{}\n".format(currentIP,currRecord,splitCurrLine[0][2::],splitCurrLine[1],splitCurrLine[2]))
            
    # Cast findings to a list for easy interation.
    findings = list(findings)
    findings.sort()

    if args.processes:
        # If using mulitprocessing, add findings to a dictionary.
        return_dict[count] = findings
    else:
        # If not using multiprocessing, just append findings to the badDomains file.
        filename = "badDomains-{}.txt".format(timestamp)
        fileBadDomains = open(filename, "w")
        for line in findings:
            fileBadDomains.write("{}".format(line))
        fileBadDomains.close()


class Logger(object):

    # Logger class used to log all stdout output to a file if the user decides to do so.
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open(str(args.outFile), "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)  

    def flush(self):
        pass    

def main():
    
    # Timestamp to keep track of filenames.
    splitTimestamp = str(time.time()).split(".")
    timestamp = splitTimestamp[0]

    # If user decides to log all stdout to a file, do that.
    if args.outFile:
        sys.stdout = Logger() 

    # Variable to keep track of execution time.
    start_time = time.time()

    if (not args.windows and not args.bind):
        print("\nYou need to choose either Bind or Windows DNS logs!\nLook at the help page (--help) for direction.\n")

    else:
        print("\nThere will be an output file with all bad domains in \nyour current working directory named badDomains-{}.txt \nwith all source IPs reaching out to bad domains, \nalong with the bad domains they reached out to.\n\nWritten by Peter Kotsiris\n".format(timestamp))


        print("Getting Started ...\n")

        # Run main functions, grabbing Umbrella logs and formatting the domains.
        auth = getAuth(str(args.apiKey), str(args.apiSecret))
        log = getUmbrellaLogs(str(args.clientID), auth, str(args.dateToSearch))
        domains = formatDomains(log)
        
        # Get Windows DNS log from SMB if desired to do so.
        if args.smb:
            print("Attempting to get DNS Log from {}. This might take a bit...\n".format(args.smb[0]))

            try:
                getFiles(args.smb[0], args.smb[1], args.smb[2], args.smb[3], args.smb[4], args.smb[5])
            except Exception as e:
                print("Something went wrong... Your SMB credentials are probably invalid.\n")
                exit()

            print("Successfully downloaded DNS Log from {}. Output file is {}\n\n".format(args.smb[0], args.smb[0]+".log"))

        print("Parsing Logs ...\n")

        # For multiprocessing
        if args.windows and args.processes:
            numProcesses = args.processes
            
            # Don't allow more than 10 processes run.
            if numProcesses > 10:
                numProcesses = 10

            # Split the domains by number of processes, store the chunks of domains in a list.
            splitBy = int(len(domains)/numProcesses)
            chunks = [domains[x:x+splitBy] for x in range(0, len(domains), splitBy)]

            procList = []
            count = 0

            # Use a Manager Dictionary to keep track of findings throughout all processes.
            manager = multiprocessing.Manager()
            return_dict = manager.dict()

            # Start multiprocessing of parseWindowsLog function.
            while True:
                try:
                    # Append all processes to a list, start them.
                    procList.append(multiprocessing.Process(target=parseWindowsLog, args=(chunks[count], timestamp, return_dict, count)))
                    procList[count].start()
                    count += 1

                except:
                    # Break after all processes have started.
                    break

            # Join all processes
            for proc in procList:
                proc.join()

        # If no multiprocessing, then just run parseWindowsLog.
        elif args.windows and not args.processes:
            parseWindowsLog(domains, timestamp, {}, 0)

        # To parse a Bind log (no multiprocessing).
        elif args.bind:
            parseBindLog(domains, timestamp)
    
    # After all findings have been added to the dictionary, add them to the badDomains output file.
    if args.windows and args.processes:
        filename = "badDomains-{}.txt".format(timestamp)
        findings = open(filename, "w")
        for index in return_dict:
            for each in return_dict[index]:
                findings.write(each)
        findings.close()

    print("\nFinished in {} seconds. View the file, badDomains-{}.txt in your current \nworking directory for all hits to bad domains.\n".format(time.time() - start_time, timestamp))
        

if __name__ == "__main__":
    main()
