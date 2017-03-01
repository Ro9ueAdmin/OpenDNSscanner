import os
import sys
import threading
from datetime import datetime
print('[!] [' + str(datetime.now().time()) + '] DNS Scanner started...')
import random
import socket
import time
from subprocess import Popen, PIPE

global scriptName
global threads
global ranged
global timeOUT
global octets
global testQuery
global octet1
global octet2
global octet3
global portOpen
global recursive
global filterMet
global sizeList
global sizeFilter

sizeList = []
recursive = 0
portOpen = 0
filterMet = 0

if len(sys.argv) < 7:
	print('  Usage: ' + str(sys.argv[0]) + ' <Threads> <Range> <Octets> <Timeout> <TestDomain> <ResponseSizeFilter>')
	print('Example: ' + str(sys.argv[0]) + ' 4000 a 94 10 obscure.com 1000')
	sys.exit()

scriptName = str(sys.argv[0])
threads = str(sys.argv[1])
ranged = str(sys.argv[2])
octets = str(sys.argv[3])
timeOUT = str(sys.argv[4])
testQuery = str(sys.argv[5])
sizeFilter = str(sys.argv[6])

print('[!] [' + str(datetime.now().time()) + ']     Threads: ' + threads)
print('[!] [' + str(datetime.now().time()) + ']       Range: ' + ranged)
print('[!] [' + str(datetime.now().time()) + ']      Octets: ' + octets)
print('[!] [' + str(datetime.now().time()) + ']     timeout: ' + str(timeOUT))
print('[!] [' + str(datetime.now().time()) + ']       Query: ' + str(testQuery))
print('[!] [' + str(datetime.now().time()) + '] Size Filter: ' + str(sizeFilter))

def scanner(id):
	global filterMet
	global sizeFilter
	global testQuery
	global recursive
	global portOpen
	global scriptName
	global threads
	global ranged
	global octets
	global timeOUT
	global octet1
	global octet2
	global octet3
	
	if ranged == 'a':
		if '.' in str(octets):
			sys.exit()
		else:
			octet1 = str(octets)
	elif ranged == 'b':
		try:
			octet1, octet2 = str(octets).split('.')
		except:
			sys.exit()
	elif ranged == 'c':
		try:
			octet1, octet2, octet3 = str(octets).split('.')
		except:
			sys.exit()
	elif ranged != 'random':
		sys.exit()

	#scan
	while 1:
		try:
			output = ''
			if ranged == 'a':
				target = octet1 + '.' + str(random.randrange(0, 256)) + '.' + str(random.randrange(0, 256)) + '.' + str(random.randrange(0, 256))
			elif ranged == 'b':
				target = octet1 + '.' + octet2 + '.' + str(random.randrange(0, 256)) + '.' + str(random.randrange(0, 256))
			elif ranged == 'c':
				target = octet1 + '.' + octet2 + '.' + octet3 + '.' + str(random.randrange(0, 256))
			elif ranged == 'random':
				target =  str(random.randrange(0, 256)) + '.' + str(random.randrange(0, 256)) + '.' + str(random.randrange(0, 256)) + '.' + str(random.randrange(0, 256))
			port = 53 ##### DNS #####
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(int(timeOUT))

#		       try:
			sock.connect((target, port))
#		       print('Port 53 open: ' + str(target))
			portOpen = portOpen + 1
			command = 'host ' + str(testQuery) + ' ' + str(target)
			stdout = Popen(command, shell=True, stdout=PIPE).stdout
			output = stdout.read()
			if ('REFUSED' not in output) and ('timed out' not in output) and ('handled' in output):
				command = 'dig ANY ' + str(testQuery) + ' @' + str(target)
				stdout = Popen(command, shell=True, stdout=PIPE).stdout
				output=stdout.read()
				if 'Truncated' not in output:
					junk, size = output.split('rcvd: ')
					recursive = recursive + 1
					size = str(size).replace('\n', '')
					if int(size) >= int(sizeFilter):
						entry = str(target) + '|' + str(size)
						sizeList.append(entry)
#					       print('Target reponse size met: ' + str(size))
						filterMet = filterMet + 1
						list = open('DNSlist.txt', 'a')
						list.write(str(target) + '|' + str(size) + '\n')
						list.close()
#		       except:
#			       pass
			sock.close()
			breaker = False
		except Exception, e:
			try:
				sock.close()
			except:
				closed = True
			pass


count = 0
for i in range(0, int(threads)):
	try:
		count = count + 1
		t = threading.Thread(target=scanner, args=(count ,))
		t.start()
	except:
		print('[!] [' + str(datetime.now().time()) + '] Could not start thread: ' + str(count))
print('[!] [' + str(datetime.now().time()) + '] Threads started: ' + str(count))
while 1:
	check = raw_input(' ')
	if str(check) != 'size':
		print('     Open port 53: ' + str(portOpen))
		print('Recursion enabled: ' + str(recursive))
		print('       Filter Met: ' + str(filterMet))
	else:
		for entry in sizeList:
			ip, size = entry.split('|')
			print('      IP: ' + str(ip))
			print('RESPONSE: ' + str(size))
			print('-----------------------------')
