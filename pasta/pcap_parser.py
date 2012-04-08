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
from subprocess import check_output
from datetime import datetime

class PcapParser:
    """Parser for pcap files"""

    def __init__(self, keep_datagrams = True):
        # TODO: Add options

        self.keep_datagrams = keep_datagrams # Boolean

    def parse(self, file):
        """Parse the given pcap file and create Connection objects"""

        streams = []
        datagrams = {}
        clients = {}
        servers = {}
        clients_protocol = {}
        servers_protocol = {}
        start_time = {}
        end_time = {}
        # TODO: Check if tshark is available

        # Read the pcap file to get the number of ssh connections streams
        for stream in check_output(
                ["tshark", "-r", file, "-Rssh", "-Tfields", "-etcp.stream"
                ]).split("\n"):
            if stream and stream not in streams:
                streams.append(stream);

        tshark_stream_string = " or ".join(["tcp.stream=="+stream
                                            for stream in streams])

        for packet in check_output([
                "tshark", "-r", file, "-R", tshark_stream_string, "-Tfields",
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
                "-essh.protocol"]).split("\n"):
            p = packet.split("\t")
            if len(p) > 12:
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
                if p[12]:
                    if sentByClient:
                        clients_protocol[p[0]] = p[12]
                    else:
                        servers_protocol[p[0]] = p[12]

                if self.keep_datagrams:
                    if p[11]:
                        ack = int(p[10])
                    else:
                        ack = -1

                    #Create Datagram objects
                    datagrams[p[0]].append(Datagram(
                        sentByClient,
                        time,
                        int(p[1]), # seq number
                        int(p[10]), # datagram len
                        int(p[9]), # payload length
                        ack))

        # Create Connection objects
        connections = []
        for k in streams:
            connections.append(Connection(
                datagrams[k],
                start_time[k],
                end_time[k] - start_time[k], # Duration
                clients[k][0], # Client ip
                servers[k][0], # Server ip
                clients[k][1], # Client port
                servers[k][1], # Server port
                clients_protocol[k],
                servers_protocol[k]))

        return connections



if __name__ == '__main__':
    # TODO: logging
    import sys
    parser = PcapParser(True)
    for conn in parser.parse(sys.argv[1]):
        print conn
        print
