#!/usr/bin/python

## Syslog Receiver for PANW next generation Firewall
##
## This is a tiny syslog server that is able to receive UDP based syslog
## entries on a specified port from PANW next generation firewall and put
## specific log field into a persistent queue when the log message
## has PCAP flag (0x80000000).
#
#Org file at https://gist.github.com/marcelom/4218010
#
## This program requires following python library:
## 1. persistent queue | https://gist.github.com/wolever/1857838 
## 2. daemonize | https://github.com/thesharp/daemonize
#

import csv
import SocketServer
import time
#from hotqueue import HotQueue
from pqueue import PersistentQueue
from daemonize import Daemonize
import logging

pid = "/var/run/psyslogd.pid"
logger = logging.getLogger(__name__)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger.setLevel(logging.DEBUG)
logger.propagate = False
fh = logging.FileHandler("/var/log/psyslogd.log", "w")
fh.setFormatter(formatter)
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
keep_fds = [fh.stream.fileno()]

#queue = HotQueue("logqueue", host="localhost", port=6379, db=1)

HOST, PORT = "0.0.0.0", 8514

logger.debug("Initialize")

HostInfo = [[str(elm) for elm in v] for v in csv.reader(open("hostconfig.txt", "r"))]

logger.debug("Initialize end")

#lineNumber = 1

class SyslogUDPHandler(SocketServer.BaseRequestHandler):

	def handle(self):
#		global lineNumber
		data = bytes.decode(self.request[0].strip(), 'utf-8')

		laengde = len(data)
		if laengde > 4:
			log_line = str(data).split(',')
			for i in HostInfo:
				re = log_line[2] in i
				if re:
					break
			if log_line[3] == "THREAT" and bool(int(log_line[28],16) & 0x80000000) and re:
				queue = PersistentQueue("/var/tmp/queue_storage_dir")
#				logger.debug(log_line[3])
#				logger.debug(log_line[28])
#				logger.debug(len(log_line))
				if len(log_line) == 45:
				# 6.0 and above
					newLogString = "%s,%s,%s,%s\n" % (log_line[2],log_line[6],log_line[22],log_line[42])
				else:
					newLogString = "%s,%s,%s\n" % (log_line[2],log_line[6],log_line[22])
##				logger.debug(newLogString)
#				newLogString = "%s@%s %s %s\n" % (lineNumber, int(time.time()), self.client_address[0], data)
				queue.put(newLogString)
				logger.debug('item' + newLogString + 'was added to a queue')
				queue.close
#			lineNumber += 1

#		if lineNumber > 10000000:
#			lineNumber = 1

#if __name__ == "__main__":
def main():
	try:
		server = SocketServer.UDPServer((HOST, PORT), SyslogUDPHandler)
		server.serve_forever()
	except (IOError, SystemExit):
		pass
#	except KeyboardInterrupt:
#		print ("Crtl+C Pressed. Shutting down.")

daemon = Daemonize(app="psyslogd", pid=pid, action=main, keep_fds=keep_fds)
daemon.start()
