# Copyright (C) 2012 The PASTA team.
# See the README file for the exhaustive list of authors.
#
# This file is part of PASTA.
#
# PASTA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PASTA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PASTA.  If not, see <http://www.gnu.org/licenses/>.



from connection import Connection, Datagram
from datetime import datetime
import logging, subprocess, sys, errno

class PcapParser:
    """Parser for pcap files"""

    def __init__(self, keep_datagrams=True):
        self.keep_datagrams = keep_datagrams # Boolean
        self.logger = logging.getLogger("PcapParser")

    def parse(self, fileName, connections_nb=None):
        """Parse the given pcap file and create Connection objects"""

        self.logger.info("Start to parse %s", fileName)

        streams = []
        datagrams = {}
        clients = {}
        servers = {}
        clients_protocol = {}
        servers_protocol = {}
        start_time = {}
        end_time = {}

        # Read the pcap file to get the number of ssh connections streams
        # FIXME: doesn't detect all ssh connections
        try:
            tsharkP1 = subprocess.Popen(
                ["tshark", "-n", "-r", fileName, "-Rssh",
                    "-Tfields", "-etcp.stream"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            self._os_error(e)
        (stdout1, stderr1) = tsharkP1.communicate()
        if tsharkP1.returncode:
            self._tshark_error(tsharkP1.returncode, stderr1)

        for stream in stdout1:
            stream = stream.strip()
            if stream and stream not in streams:
                self.logger.debug("Stream found: %s", stream)
                streams.append(stream);
                clients_protocol[stream] = None
                servers_protocol[stream] = None

        if streams:
            self.logger.info("%d connections found" % len(streams))
        else:
            self.logger.warning("No connection found")
            return []

        # Select only needed tcp streams
        if connections_nb is None:
            streams_selected = streams
        else:
            streams_selected = [streams[j-1] for j in connections_nb
                                if j-1 in range(len(streams))]

        tshark_stream_string = " or ".join(["tcp.stream==" + stream
                                            for stream in streams_selected])

        # Read the pcap file to get the packet informations
        try:
            tsharkP2 = subprocess.Popen([
                    "tshark", "-n", "-r", fileName, "-R", tshark_stream_string,
                    "-Tfields",
                    "-etcp.stream",
                    "-etcp.seq",
                    "-eframe.time",
                    "-eip.src",
                    "-eipv6.src", # Nothing more elegant than two ip requests ?
                    "-etcp.srcport",
                    "-eip.dst",
                    "-eipv6.dst", # Nothing more elegant than two ip requests ?
                    "-etcp.dstport",
                    "-etcp.len",
                    "-eframe.len",
                    "-etcp.ack",
                    "-essh.protocol"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            self._os_error(e)
        (stdout2, stderr2) = tsharkP2.communicate()
        if tsharkP2.returncode:
            self._tshark_error(tsharkP2.returncode, stderr2)

        for packet in stdout2.split("\n"):
            p = packet.split("\t")
            if len(p) > 12:
                try:
                    if p[3]:
                        src = (p[3], int(p[5]))
                    else:
                        src = (p[4], int(p[5]))
                    if p[6]:
                        dst = (p[6], int(p[8]))
                    else:
                        dst = (p[7], int(p[8]))
                    time = datetime.strptime(p[2][:-3], "%b %d, %Y %H:%M:%S.%f")
                    end_time[p[0]] = time # Keep last know time for duration

                    if p[0] not in datagrams.keys(): # This is a new connection
                        datagrams[p[0]] = []
                        clients[p[0]] = src
                        servers[p[0]] = dst
                        start_time[p[0]] = time

                    sentByClient = clients[p[0]] == src

                    # Get protocol name if available
                    protocol = p[12].decode('string-escape').strip()
                    if protocol:
                        if sentByClient:
                            clients_protocol[p[0]] = protocol
                        else:
                            servers_protocol[p[0]] = protocol

                    if self.keep_datagrams:
                        #Create Datagram objects
                        new_datagram = Datagram(
                            sentByClient,
                            time,
                            int(p[1]), # seq number
                            int(p[10]), # datagram len
                            int(p[9]), # payload length
                            int(p[11]) if p[11] else -1 # datagram acked
                            )
                        datagrams[p[0]].append(new_datagram)
                        self.logger.debug("New datagram: %s", new_datagram)
                except ValueError as e:
                    # catch conversions for int, datetime...
                    self.logger.error('Parsing tshark output: %s' % e.message)
                    sys.stderr.write('Error while parsing tshark output\n')
                    sys.exit(1)

        # Create Connection objects
        connections = []
        for k in streams_selected:
            connections.append(Connection(
                streams.index(k) + 1, # Connection nb
                datagrams[k],
                start_time[k],
                end_time[k] - start_time[k], # Duration
                clients[k][0], # Client ip
                servers[k][0], # Server ip
                clients[k][1], # Client port
                servers[k][1], # Server port
                clients_protocol[k],
                servers_protocol[k]))
            self.logger.debug("New connection: %s", connections[-1].summary())

        self.logger.info("Parsing %s finished", fileName)
        return connections

    def _os_error(self, e):
        """Handle an OSError exception"""
        self.logger.error('Tshark call raises OSERROR: %s' % e.strerror)
        errors = {
            errno.ENOENT: 'Tshark is required to use PASTA',
            errno.EACCES: 'Permission denied when executing tshark',
            }
        if e.errno in errors:
            sys.stderr.write('%s\n' % errors[e.errno])
        else:
            sys.stderr.write('Error while calling tshark: %s\n' % e.strerror)
        sys.exit(1)

    def _tshark_error(self, code, stderr):
        """Handle an error from tshark call"""
        self.logger.error('Tshark exited with exit status %d' % code)
        for line in stderr.split("\n"):
            line = line.strip()
            if line:
                sys.stderr.write('%s\n' % line)
        sys.exit(1)



if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s    %(levelname)7s    %(name)11s    %(message)s',
        level=logging.INFO)
    if len(sys.argv) > 1:
        parser = PcapParser(True)
        for conn in parser.parse(sys.argv[1], set([2])):
            print "\n" + str(conn)
    else:
        print "usage: pcap_parser.py file"
