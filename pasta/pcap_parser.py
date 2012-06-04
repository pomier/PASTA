#!/usr/bin/python2.7

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

    def __init__(self, keep_datagrams=True, tshark_cmd='tshark'):
        self.keep_datagrams = keep_datagrams # Boolean
        self.tshark_cmd = tshark_cmd
        self.logger = logging.getLogger("PcapParser")
        self.streams = []
        self.datagrams = {}
        self.clients = {}
        self.servers = {}
        self.clients_protocol = {}
        self.servers_protocol = {}
        self.clients_algos = {}
        self.servers_algos = {}
        self.ssh_streams = {}
        self.start_time = {}
        self.end_time = {}
        self.file_name = ""

    def parse(self, file_name, connections_nb=None, only_ssh=True):
        """Parse the given pcap file and create Connection objects"""

        self.logger.info("Start to parse %s", file_name)
        self.file_name = file_name

        ports = self.extract_ports()

        # get infos about the streams
        self.extract_streams(ports, only_ssh)

        # Select only needed tcp streams
        if connections_nb:
            streams_selected = [self.streams[j-1] for j in connections_nb
                                if j-1 in range(len(self.streams))]
        else:
            streams_selected = self.streams

        if self.keep_datagrams:
            self.extract_datagrams(ports, streams_selected)

        # Create Connection objects
        connections = []
        for k in streams_selected:
            connections.append(Connection(
                self.streams.index(k) + 1, # Connection nb
                self.datagrams[k],
                self.start_time[k],
                self.end_time[k] - self.start_time[k], # Duration
                self.clients[k][0], # Client ip
                self.servers[k][0], # Server ip
                self.clients[k][1], # Client port
                self.servers[k][1], # Server port
                self.clients_protocol[k],
                self.servers_protocol[k],
                self.clients_algos[k],
                self.servers_algos[k],
                self.ssh_streams[k]))
            self.logger.debug("New connection: %s", connections[-1].summary())

        self.logger.info("Parsing %s finished", file_name)
        return connections


    def extract_ports(self):
        """Extract the port numbers of tcp conversations"""

        ports = set()

        try:
            tshark = subprocess.Popen(
                [self.tshark_cmd, "-n", "-r", self.file_name, "-qzconv,tcp"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            self._os_error(e)
        (stdout, stderr) = tshark.communicate()
        if tshark.returncode:
            self._tshark_error(tshark.returncode, stderr)

        lines = stdout.split("\n")
        if len(lines) > 6:
            for line in lines[5:-2]:
                line = [a for a in line.split(" ") if a]
                try:
                    ports.add(int(line[0].split(":")[-1]))
                    ports.add(int(line[2].split(":")[-1]))
                except ValueError as e:
                    self._parse_error(e)

        return ports


    def extract_streams(self, ports, only_ssh):
        """Decode ports as ssh, and get the packets 'ssh.protocol'"""

        # FIXME: in case of not only_ssh, redundant with extract_datagrams

        args = [
            self.tshark_cmd, "-n", "-r", self.file_name,
            "-Rssh.protocol" if only_ssh else "-Rtcp",
            "-Tfields",
            "-etcp.stream",
            "-eframe.time",
            "-eip.src",
            "-eipv6.src",
            "-etcp.srcport",
            "-eip.dst",
            "-eipv6.dst",
            "-etcp.dstport",
            "-essh.protocol",
            "-essh.message_code"]

        for port in ports:
            args.append("-dtcp.port==%d,ssh" % port)

        try:
            tshark = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            self._os_error(e)
        (stdout, stderr) = tshark.communicate()
        if tshark.returncode:
            self._tshark_error(tshark.returncode, stderr)

        for p in [l.split("\t") for l in stdout.split("\n")]:
            if len(p) < 10:
                continue

            try:
                src = (p[2] if p[2] else p[3], int(p[4]))
                dst = (p[5] if p[5] else p[6], int(p[7]))

                if p[0] not in self.datagrams.keys():
                    # This is a new connection
                    self.streams.append(p[0])
                    self.datagrams[p[0]] = []
                    time = datetime.strptime(
                        p[1][:-3], "%b %d, %Y %H:%M:%S.%f")
                    self.start_time[p[0]] = time
                    self.end_time[p[0]] = time
                    self.clients_protocol[p[0]] = None
                    self.servers_protocol[p[0]] = None
                    self.clients_algos[p[0]] = None
                    self.servers_algos[p[0]] = None
                    self.ssh_streams[p[0]] = False
                    # assume the first packet of the connection
                    # is send by the client
                    self.clients[p[0]] = src
                    self.servers[p[0]] = dst

                # if datagram detected as ssh, the stream is a ssh connection
                if p[9] or only_ssh:
                    self.ssh_streams[p[0]] = True

                # Get protocol name if available
                protocol = p[8].decode('string-escape')
                if protocol:
                    # if first time we see a protocol and we don't know who is
                    # the client/server, set them
                    if self.servers_protocol[p[0]] is None:
                        self.clients[p[0]] = dst
                        self.servers[p[0]] = src
                    # set the protocol field
                    if self.clients[p[0]] == src:
                        self.clients_protocol[p[0]] = protocol
                    else:
                        self.servers_protocol[p[0]] = protocol

            except ValueError as e:
                # catch conversions for int, datetime...
                self._parse_error(e)


    def extract_datagrams(self, ports, streams):
        """Get datagrams from streams"""

        if not streams:
            return

        tshark_stream_string = " or ".join(["tcp.stream==" + stream
                                            for stream in streams])

        # Read the pcap file to get the packet informations
        args = [
                "tshark", "-n", "-r", self.file_name,
                "-R", tshark_stream_string,
                "-Tfields",
                "-etcp.stream",
                "-etcp.seq",
                "-eframe.time",
                "-etcp.len",
                "-eframe.len",
                "-etcp.ack",
                "-eip.src",
                "-eipv6.src",
                "-etcp.srcport",
                "-essh.kex_algorithms",
                "-essh.server_host_key_algorithms",
                "-essh.encryption_algorithms_client_to_server",
                "-essh.encryption_algorithms_server_to_client",
                "-essh.mac_algorithms_client_to_server",
                "-essh.mac_algorithms_server_to_client",
                "-essh.compression_algorithms_client_to_server",
                "-essh.compression_algorithms_server_to_client",
                ]

        for port in ports:
            args.append("-dtcp.port==%d,ssh" % port)

        try:
            tshark = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            self._os_error(e)
        (stdout, stderr) = tshark.communicate()
        if tshark.returncode:
            self._tshark_error(tshark.returncode, stderr)

        for p in [l.split("\t") for l in stdout.split("\n")]:
            if len(p) < 17:
                continue

            try:
                src = (p[6], int(p[8])) if p[6] else (p[7], int(p[8]))
                time = datetime.strptime(p[2][:-3],
                                         "%b %d, %Y %H:%M:%S.%f")
                self.end_time[p[0]] = time # Keep last know time for duration

                # create Datagram objects
                new_datagram = Datagram(
                    self.clients[p[0]] == src, # sent by client
                    time,
                    int(p[1]), # seq number
                    int(p[4]), # datagram len
                    int(p[3]), # payload length
                    int(p[5]) if p[5] else -1 # datagram acked
                    )
                self.datagrams[p[0]].append(new_datagram)
                self.logger.debug("New datagram: %s", new_datagram)
                # Algos
                if any(p[i] for i in xrange(9, 17)):
                    algos = {
                            "kex_algorithms": p[9],
                            "server_host_key_algorithms": p[10],
                            "encryption_algorithms_client_to_server": p[11],
                            "encryption_algorithms_server_to_client": p[12],
                            "mac_algorithms_client_to_server": p[13],
                            "mac_algorithms_server_to_client": p[14],
                            "compression_algorithms_client_to_server": p[15],
                            "compression_algorithms_server_to_client": p[16],
                        }
                    if self.clients[p[0]] == src:
                        self.clients_algos[p[0]] = algos
                    else:
                        self.servers_algos[p[0]] = algos
            except ValueError as e:
                # catch conversions for int, datetime...
                self._parse_error(e)


    def _os_error(self, e):
        """Handle an OSError exception"""
        self.logger.error('Tshark call raises OSERROR: %s' % e.strerror)
        errors = {
            errno.ENOENT: 'Tshark is required to use PASTA\n'
                'The tshark binary used was %s; to change it, use the'
                ' --tshark option.' % self.tshark_cmd,
            errno.EACCES: 'Permission denied when executing tshark\n'
                'Make sure you can execute %s' % self.tshark_cmd,
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

    def _parse_error(self, e):
        """Handle an conversion error while parsing"""
        self.logger.error('Parsing tshark output: %s' % e.message)
        sys.stderr.write('Error while parsing tshark output\n')
        sys.exit(1)


if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s    %(levelname)7s    %(name)11s    %(message)s',
        level=logging.INFO)
    if len(sys.argv) > 1:
        parser = PcapParser(True)
        for conn in parser.parse(sys.argv[1]):
            print "\n" + str(conn)
    else:
        print "usage: pcap_parser.py file"
