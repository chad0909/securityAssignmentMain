import nmap
dict = nmap.PortScanner()
print('Please Enter the IPAddress for Analysis!')
ipAd = str(input())
print('Please wait until the process is finished...')
dict.scan(hosts=ipAd, ports=None, arguments='-A')
for host in dict.all_hosts():
    lport = dict[host]['tcp'].keys()
    sorted(lport)
    print("Process Finished. IP %s has following information" % ipAd)
    print()
    for port in lport:
        state = str(dict[host]['tcp'][port]['state'])
        product = str(dict[host]['tcp'][port]['product'])
        version = str(dict[host]['tcp'][port]['version'])
        name = str(dict[host]['tcp'][port]['name'])

        print('PORT: %s\tSTATE: %s\tPORTNAME: %s\tPRODUCT: %s\tVERSION: %s' %(port, state, name, product, version))
        print()

print("For more information press 'Y'")
a = str(input())
if a == "Y":
    print(dict.scan(hosts=ipAd, ports=None, arguments='-A'))
else:
    print("Thankyou for Using")

