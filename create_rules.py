import re
from urlparse import urlparse

def findString(f, l, data):
    key = re.search(re.escape(f) + '(.*?)' + re.escape(l), data)
    if key == None:
        return None
    return key.group(1)


def addRules(ruleName, port, httpQuery, hostName, count, failedRule):
    global out

    if port == 80:
        out.write('alert tcp any any -> any %d (msg:"%s rule"; content:"GET %s"; content:"Host: %s"; sid:%d; rev:1;)' % (port, ruleName, httpQuery, hostName, count))
    else:
        if failedRule == True:
            out.write('# Cannot create rule -> https://%s%s' % (ruleName, httpQuery))
        else:
            out.write('alert tcp any any -> any %d (msg:"https %s rule"; content:"%s"; content:"http/1."; sid:%d; rev:1;)' % (port, ruleName, hostName, count))
    out.write("\n")
    return


inp = open("rawrules.txt", "r")
out = open("bob.rules", "w")

lines = inp.readlines()
count = 10000

for line in lines:
    count += 1
    url = urlparse(line[:-1])
    path = '/'
    if len(url.path) != 0:
        path = url.path

    query = ''
    if len(url.query) > 0:
        query = path + "?" + url.query
    else:
        query = path
    
    port = 80
    failedRule = False
    if url.scheme == 'https':
        port = 443
        if query != '/':
            failedRule = True

    addRules(url.netloc, port, query, url.netloc, count, failedRule)
inp.close()
out.close()

