# Author: Bogdan Kovch
# Date:   July 17, 2013

import dpkt # not a standard python library, need to download and install it manually
            # URL: http://code.google.com/p/dpkt/downloads/list
import time
import sys
import socket
from optparse import OptionParser # for parsing command-line arguments
from dpkt.ethernet import Ethernet

# globals
IP = socket.gethostbyname(socket.gethostname()) # local IP address (ex.: 192.168.1.112)
# IP = '' # localhost IP address (ex.: 127.0.0.1)
# IP = "eth0" # localhost ???
# IP = "eth1" # send directly to network adapter ???
PORT = 35001 # port number defined by OS
# PORT = 36000
MAX_IDLE_TIME = 30 # maximum time (in seconds) interval between packets. Need to skip long intervals.

def main():
    """ This function acts like a hub for the rest of the code in the program. """
    global sock
    parseArgs()
    showOptions()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    processFrames()

def parseArgs():
    """ This function parses command-line arguments into program options. """
    global options
    # Parse command-line arguments
    parser = OptionParser()
    parser.add_option("-f", "--file", action="store", type="string", dest="filename",
            help="pcap file containing files to be retransmitted", default="2013-06-30-1.pcap")
    parser.add_option("-s", "--skip", action="store", type="int", dest="skip_time",
            help="time in seconds to skip at the beginning", default="2453")
    parser.add_option("-t", "--fast", action="store_true", dest="fast",
            help="send packets immediately one after another ignoring time intervals", default=False)
    parser.add_option("-d", "--debug", action="store_true", dest="debug",
            help="show debug messages", default=False)
    (options, args) = parser.parse_args()

def showOptions():
    """ This function displays current program options. """
    print "Options:"
    print "  filename: ", options.filename
    print "  skip time:", options.skip_time, "seconds"
    print "  fast:     ", options.fast
    print "  debug:    ", options.debug    

def processFrames():
    """ This function loads frames from the .pcap file specified and processes them. """
    global sock
    # local variables
    num_frames = 0      # total number of frames loaded from the file
    ts_first = 0        # timestamp of the very first frame in the file
    ts_prev = 0         # timestamp of the frame processed previously
    ts_start = 0        # timestamp of the first processed frame (after options.skip_time)
    time_str = ''       # time lable of the current frame (for debug output)
    time_str_prev = ''  # time lable of the previous frame (for debug output)

    # open the file
    f = open(options.filename, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    # read the very first frame only
    for ts, pkt in pcap: 
        ts_first = ts # retrieve the very first timestamp
        break # sorry... not the most elegant way to access a single element
    
    if options.debug:
        print "Frames (second, frames during that second):"
    
    # read all frames from the file and process them
    for ts, pkt in pcap:
        ts_offset = ts - ts_first # timestamp offset from the very first frame timestamp
        if ts_offset < options.skip_time: # skip frames during skip_time at the beginning
            continue
        if num_frames <= 0: # reset ts_prev and ts_start at the beginning of packet processing
            ts_prev = ts
            ts_start = ts
        if not options.fast: # send packets with intervals according to their timestamps
            sleep_time = ts - ts_prev
            if sleep_time > MAX_IDLE_TIME:
                if options.debug:
                    print ""
                    print "  The server was supposed to stay idle for %.1f minutes here." % (sleep_time / 60.0),
                    print "Idle time period skipped.",
            else:
                time.sleep(sleep_time)
        ts_prev = ts
        
        # ================================= debug output =================================
        if options.debug:
            time_str = "%6.0f" % ts_offset
            if time_str_prev <> time_str:
                if num_frames > 0:
                    print ""
                print time_str, "",
            sys.stdout.write('.')
            time_str_prev = time_str
        # ================================================================================
        
        data = extractData(ts, pkt)
        if data != None:
            sock.sendto(data, (IP, PORT))
        num_frames += 1

    print "" # add newline to output
    print "total %d frames sent within %.2f seconds (%.2f minutes):" % (num_frames, ts_prev-ts_start, (ts_prev-ts_start)/60.0 )

def extractData(ts, pkt):
    """ This functions send a network packet """
    global sock
    
    # link layer (ethernet)
    eth = dpkt.ethernet.Ethernet(pkt)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        if options.debug:
            sys.stdout.write("[not IPv4]")
        return None
        
    # network layer (IPv4)
    ip = eth.data
    if ip.p != dpkt.ip.IP_PROTO_UDP:
        if options.debug:
            sys.stdout.write("[not UDP]")
        return None
    
    # transport layer (UDP)
    udp = ip.data
    return udp.data
    
if __name__ == "__main__":
    main()