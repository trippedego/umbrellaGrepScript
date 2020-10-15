import argparse
import time 
import re
import requests
import json
import base64
import sys

parser = argparse.ArgumentParser()
parser.add_argument("dnsLog", type=str, help="Windows DNS Log to parse")
parser.add_argument("apiKey", type=str, help="Umbrella Reporting API Key")
parser.add_argument("apiSecret", type=str, help="Umbrella Reporting API Secret")
parser.add_argument("clientID", type=str, help="Umbrella Client ID for Organization")
parser.add_argument("dateToSearch", type=str, help="How far back you want to look for logs in Umbrella, from 1 day to 30 days. EX: 30 (for 30 days)")
parser.add_argument("-o", "--outFile", type=str, help="Name of file to save command output to.")
args = parser.parse_args()

def getAuth(apiKeyArg, apiSecretArg):

    apiToken = (base64.b64encode(apiKeyArg + ":" + apiSecretArg))

    authURL = "https://management.api.umbrella.com/auth/v2/oauth2/token"

    authHeaders = {
        "accept": "application/json",
        "Authorization": "Basic {}".format(apiToken)
    }

    response = requests.request("GET", authURL, headers=authHeaders)
    
    cleanedResponse = response.text.split(",")
    for line in cleanedResponse:
        if (line.find("access_token") != -1):
            tempLine = line[16::]
            onlyAuth = tempLine[:-1]
    
    return onlyAuth

def getDomains(clientIDArg, oAuthToken, umbrellaDate):
    domainURL = "https://reports.api.umbrella.com/v2/organizations/{}/activity".format(clientIDArg)

    formattedDate = "-{}days".format(str(umbrellaDate))

    domainPayload = {"from":formattedDate,"to":"now","limit":"10","categories":"65"}

    domainHeaders = {
        "accept": "application/json",
        "authorization": "Bearer {}".format(oAuthToken)
    }

    response = requests.request("GET", domainURL, headers=domainHeaders, params=domainPayload)
    return response.text

def formatDomains(umbrellaLogs):

    allLines = umbrellaLogs.split(",")
    badDomains = list()
    print "\nDomains grabbed from Umbrella:\n"
    for line in allLines:
        if (line.find("domain") != -1):
            tempLine = line[10::]
            cleanedDomain = tempLine[:-1]
            badDomains.append(cleanedDomain.rstrip())

    badDomains = list(set(badDomains))
    for domain in badDomains:
        print domain
    print "\n"
    return badDomains


def parseLog(badDomains):
    log = open(args.dnsLog, "r").read().split("\r\n")
    tempBadDomains = open("badDomains.txt", "w")
    
    log.sort()
    badDomains.sort()
    findings = set()
    for line in log:
        if line == '':
            continue

        splitCurrLine = line.split(' ')

        try:
            currentIP = splitCurrLine[9]
        except:
            continue

        currRecord = splitCurrLine[-1]

        splitRERecord = re.split("\(\d+\)",currRecord)
        fixedDNSRecord= ""
        tempRE = ""
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
        currRecord=(valRE[0:-2])
        
        splitDomain = list()
        for currRecord in badDomains:
            try:
                splitDomain = splitRE[-3].find(currRecord)
            except:
                continue
            
            splitDomain = currRecord.split('.')
            
            if splitRE[-3].find(splitDomain[-2]) != -1:
                if line.find("208.67.220.220") != -1 or line.find("208.67.222.222") != -1 or line.find("127.0.0.1") != -1:
                    continue
                else:
                    findings.add("{} is reaching out to {}\n".format(currentIP,currRecord))
            
    findings = list(findings)
    findings.sort()

    for line in findings:
        print line
        tempBadDomains.write("{}".format(line))
    tempBadDomains.close()

class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open(str(args.outFile), "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)  

    def flush(self):
        pass    

def main():
    if args.outFile:
        sys.stdout = Logger() 
    print "\nThere will be an output file with all bad domains in \nyour current working directory named badDomains.txt \nwith all source IPs reaching out to bad domains, \nalong with the bad domains they reached out to.\n\nWritten by Peter Kotsiris\n"
    time.sleep(2)
    print "Getting Started ...\n" 
    auth = getAuth(str(args.apiKey), str(args.apiSecret))
    log = getDomains(str(args.clientID), auth, str(args.dateToSearch))
    domains = formatDomains(log)
    print "Parsing Log ...\n"
    parseLog(domains)
    print "\nFinished, view the file, badDomains.txt in your current \nworking directory for all hits to bad domains.\n"
    

if __name__ == "__main__":
    main()