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



import logging

class ConnectionType():

    # Configuration constants

    # To be part of a shell interaction
    shell_max_time_to_reply = 0.7 # max nb of RTTs
    shell_min_replies = 0.6 # min ratio of replies

    # To be part of a reverse shell interaction
    rshell_max_time_to_reply = 0.7 # max nb of RTTs
    rshell_min_replies = 0.6 # min ratio of replies

    # To be part of a SCP connection
    scp_min_asymetry = 0.95 # min asymetry if server sent more
    rscp_max_asymetry = 0.05 # max asymetry if client sent more

    def __init__(self, connection):
        self.connection = connection
        self.time_to_reply = {True: [], False: []}
        self.ratio_server_sent = 0
        self.logger = logging.getLogger('Conn%dType' % connection.nb)

    def compute(self):
        """Find the type of the ssh connection"""
        self.logger.info('Start computation')

        # compute time to reply
        self.compute_time_to_reply()

        # shell (True) and reverse shell (False)
        name = {True: 'shell', False: 'reverse shell'}
        max_time_to_reply = {True: ConnectionType.shell_max_time_to_reply,
                             False: ConnectionType.rshell_max_time_to_reply}
        min_replies = {True: ConnectionType.shell_min_replies,
                       False: ConnectionType.rshell_min_replies}
        possible = {True: False, False: False} # defaults to False
        for way in (True, False): # for both shell and reverse shell
            if len(self.time_to_reply[way]): # is there replies in this way?
                # consider only the replies below the threshold
                replies_to_consider = sum(1 for t in self.time_to_reply[way]
                                          if t <= max_time_to_reply[way])
                replies_total = len(self.time_to_reply[way])
                # compute the ratio
                ratio = float(replies_to_consider) / float(replies_total)
                self.logger.debug('Replies ratio for %s: %.2f'
                                  ' (min %.2f required)'
                        % (name[way], ratio, min_replies[way]))
                # given the ratio, make the decision
                possible[way] = ratio >= min_replies[way]
        # recopy the decisions
        possible_shell = possible[True]
        possible_rshell = possible[False]

        # compute asymetry
        self.compute_asymetry()

        # scp up (True) and scp down (False)
        if self.ratio_server_sent > 0.5:
            # scp
            self.logger.debug('Asymetry ratio for direct scp: %.2f'
                              ' (min %.2f required)' % (self.ratio_server_sent,
                                  ConnectionType.scp_min_asymetry))
            possible_scp = self.ratio_server_sent \
                            >= ConnectionType.scp_min_asymetry
            possible_rscp = False
        else:
            # reverse scp
            self.logger.debug('Asymetry ratio for reverse scp: %.2f'
                              ' (max %.2f required)' % (self.ratio_server_sent,
                                  ConnectionType.rscp_max_asymetry))
            possible_rscp = self.ratio_server_sent \
                            <= ConnectionType.rscp_max_asymetry
            possible_scp = False

        # choose connection type (order of the conditions is important)
        if possible_scp:
            self.connection.connectionType = 'scp (up)'
        elif possible_rscp:
            self.connection.connectionType = 'scp (down)'
        elif possible_shell:
            self.connection.connectionType = 'shell'
        elif possible_rshell:
            self.connection.connectionType = 'reverse shell'
        else:
            self.connection.connectionType = 'tunnel'

        self.logger.info('Computations finished: type is %s'
                % self.connection.connectionType)

    def compute_asymetry(self):
        """Compute the asymetry of the connection"""
        clientSent = float(sum(p.payloadLen for p in self.connection.datagrams
                               if p.sentByClient))
        serverSent = float(sum(p.payloadLen for p in self.connection.datagrams
                               if not p.sentByClient))
        if serverSent == 0.0:
            # be sure not to have a division by zero error
            self.ratio_server_sent = 0.0
        else:
            self.ratio_server_sent = serverSent / (serverSent + clientSent)

    def compute_time_to_reply(self):
        """Compute the times to reply"""
        # True: time for the server to reply
        # False: time for the client to reply
        self.time_to_reply = {True: [], False: []}
        last_datagram = {True: None, False: None}
        for datagram in self.connection.datagrams:
            if not datagram.payloadLen:
                # no payload, skip
                continue
            way = not datagram.sentByClient
            if last_datagram[way] is not None \
                    and last_datagram[way].RTT.total_seconds():
                # a reply
                self.time_to_reply[way].append(
                    (datagram.time - last_datagram[way].time).total_seconds() /
                    last_datagram[way].RTT.total_seconds()
                    )
            last_datagram[way] = None
            last_datagram[not way] = datagram
