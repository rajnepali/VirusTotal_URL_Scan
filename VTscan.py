#!/usr/bin/python

__author__ = "Raj Nepali"
__Version__ = "$Revision 2.0 $"
__date__ = "$Date: 2015/01/13 $"
__license__ = "Python"

import time
import json
import sys
import urllib, urllib2
import requests

def check_VT(url):
    retrieve_url="https://www.virustotal.com/vtapi/v2/url/report"
    retrieve_parameters ={"resource":url, "apikey":"YOUR_KEY_GOES_HERE"}
    
    #retrieve
    ret_data=urllib.urlencode(retrieve_parameters)
    ret_req=urllib2.Request(retrieve_url,ret_data)
    ret_response=urllib2.urlopen(ret_req)
    ret_json=ret_response.read()
    response_dict=json.loads(ret_json)
    
    #The idea here is that if any one scanning service lists the URL as malicious, we consider it as malicious
    if (('positives' in response_dict)==True):
        VT_result= response_dict['positives']
        if (VT_result >0 ): #if any one service says its malicious, then it is malicious
            status = "True"
        else:
            status = "False"
        return status
    else:
        status = "Not Found!!!"
        return status

for file in sys.argv[1:]:
  try:
    open(file, 'r')
  except Exception as ex:
    print "Error: %s"%str(ex)

  for line in file:
    try:
      line.strip('\n')           
      VT_result = check_VT(line) #submit full_url to virustotal for checking
      print VT_result
    except Exception as e:               
      print "Error: %s"%str(ex)

