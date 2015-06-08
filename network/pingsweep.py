import subprocess

for ping in range(1,254):
    address = "192.168.33." + str(ping)
    res = subprocess.call(['ping', '-c', '1', address])
    if res == 0:
        print "ping to", address, "OK"
