# looks like the formatting is a bit off. that's the next tod0

import sys, json, urllib2, base64, requests, os, re, time , string
from requests.auth import HTTPBasicAuth


FIR_API_URL = "https://fir.telecom.tcnz.net/api/"

headers = {
'Authorization' : 'Token ',
'Content-type' : 'application/json'
}

if __name__ == '__main__':
    try:
        import splunk.Intersplunk as si
    except Exception, e:
        si.generateErrorResults("Intersplunk import failed")
     
    try:
        outputresults = []
        results,dummyresults,settings = si.getOrganizedResults()
        i=0
		    category=0;
        now = str(int(time.mktime(time.gmtime())))
        for result in results:
            if i==0:
				#  category is IDS State table alert
				if result['category']==1:
					datetime=(sorted (re.findall("\d{2}\/\d{2}\/\d{2}\s\d{2}:\d{2}:\d{2}\s" , results), reverse=True))[0]
					sensors=', '.join(set(re.findall("\sesm\w+?\W+?\w+?\s",results)))
					signatures=" * "+"\n * ".join(list(set(re.findall("snort:\s\[1:\d+:\d+\].*{\w+}",results))))
					sourceip= ' , '.join(set(re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ','.join(re.findall("\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s->)",results)))))
					xforward= ' , '.join(re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",repr(set(re.findall("(\d{2}\/\d{2}\/\d{2,4})\s(\d{2}:\d{2}:\d{2})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",results)))))
					sport= string.replace(', '.join(set(re.findall(":\d+\s" , repr(re.findall("\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s->)",results))))),":","")
					destip= ' , '.join(set(re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",repr(re.findall("->\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+",results)))))
					dport= string.replace(' , '.join(set(re.findall(":\d+" , repr(re.findall("->\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)",results))))),":","")
					data = {
						"actor" : "0",
						"category": "0",
						"confidentiality": "1",
						"description": "Pushed from Splunk by "+result['splunkuser']\
						+"**BRIEF**\r\n\r\n"\
						+"* DateTime: " + datetime\
						+"\r\n\r\n* Sensors: "+sensors\
						+"\r\n\r\n* Signatures:\r\n\r\n"+signatures\
						+"\r\n\r\n* PCAP Attached: "\
						+"\r\n\r\n**SOURCE**\r\n\r\n"\
						+"\r\n Source IP(s): "+sourceip\
						+"\r\n X-Forward-For : (Please Confirm with PCAP) "+xforward\
						+"Ports: "+sport\
						+"\r\n Hostname: "\
						+"\r\n\r\n**Destination**\r\n\r\n"\
						+"\r\n Destination IP(s): "+destip\
						+"Ports: "+dport\
						+"\r\n Hostname: "\
						+"\r\n\r\n**Add RAW data as a Nugget**\r\n\r\n",
								"plan" : "0",
								"concerned_business_lines" : [1],
								"severity": "3",
								"is_incident" : "true",
								"status" : "O",
								"subject": "IDS Event:  "
						}		
        			response = requests.post(FIR_API_URL+"incidents", headers=headers, data=json.dumps(data), verify=False)
                    outputresults.append({'fir_api' : result['dest'], 'push_status' : 'ok'})	
            	i=1  											    
        si.outputResults(outputresults)

    except Exception, e:
        import traceback
        stack =  traceback.format_exc()
        si.generateErrorResults("Error '%s'. %s" % (e, stack))
