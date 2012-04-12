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
    shell_max_time_to_reply = 1.5 # max nb of RTTs
    shell_min_replies = 0.5 # min ratio of replies

    # To be part of a SCP connection
    scp_min_asymetry1 = 0.95 # min asymetry if server sent more
    scp_max_asymetry2 = 0.05 # max asymetry if client sent more

    # To be part of a tunneled connection
    tunnel_min_time_to_reply = 1.5 # min nb of RTTs
    tunnel_max_time_to_reply = 9999999999 # max nb of RTTs
    tunnel_min_replies = 0.5 # min ratio of replies
    tunnel_min_asymetry1 = 0.8 # min asymetry if server sent more
    tunnel_max_asymetry2 = 0.2 # max asymetry if client sent more

    def __init__(self, connection):
        self.connection = connection
        self.time_to_reply = []
        self.ratio_server_sent = 0
        self.logger = logging.getLogger('Conn%dType' % connection.ID)

    def compute(self):
        """Find the type of the ssh connection"""
        self.logger.info('Start computation')

        possible_shell = True
        possible_scp = True
        possible_tunnel = True

        # compute number of related replies
        self.compute_time_to_reply()
        replies_total = len(self.time_to_reply)
        if replies_total:
            replies_shell = sum(1 for t in self.time_to_reply
                                if t <= ConnectionType.shell_max_time_to_reply)
            replies_tunnel = sum(1 for t in self.time_to_reply
                                 if ConnectionType.tunnel_min_time_to_reply <= t \
                                    <= ConnectionType.tunnel_max_time_to_reply)
            ratio_shell = float(replies_shell) / float(replies_total)
            ratio_tunnel = float(replies_tunnel) / float(replies_total)
            self.logger.debug('Replies ratio for shell: %.2f (min %.2f required)'
                    % (ratio_shell, ConnectionType.shell_min_replies))
            self.logger.debug('Replies ratio for tunnel: %.2f (min %.2f required)'
                    % (ratio_tunnel, ConnectionType.tunnel_min_replies))
            possible_shell &= ratio_shell >= ConnectionType.shell_min_replies
            possible_tunnel &= ratio_tunnel >= ConnectionType.tunnel_min_replies
        else:
            self.logger.warning('No replies to get information from')
            possible_shell = False
            possible_tunnel = False

        # compute asymetry
        self.compute_asymetry()
        if self.ratio_server_sent > 0.5:
            self.logger.debug('Asymetry: server sent more than client')
            self.logger.debug('Asymetry ratio for scp: %.2f'
                              ' (min %.2f required)' % (self.ratio_server_sent,
                                  ConnectionType.scp_min_asymetry1))
            self.logger.debug('Asymetry ratio for tunnel: %.2f'
                              ' (min %.2f required)' % (self.ratio_server_sent,
                                  ConnectionType.tunnel_min_asymetry1))
            possible_scp &= self.ratio_server_sent \
                            >= ConnectionType.scp_min_asymetry1
            possible_tunnel &= self.ratio_server_sent \
                               >= ConnectionType.tunnel_min_asymetry1
        elif possible_tunnel:
            self.connection.connectionType = 'tunnel'
        else:
            self.logger.debug('Asymetry: client sent more than server')
            self.logger.debug('Asymetry ratio for scp: %.2f'
                              ' (max %.2f required)' % (self.ratio_server_sent,
                                  ConnectionType.scp_max_asymetry2))
            self.logger.debug('Asymetry ratio for tunnel: %.2f'
                              ' (max %.2f required)' % (self.ratio_server_sent,
                                  ConnectionType.tunnel_max_asymetry2))
            possible_scp &= self.ratio_server_sent \
                            <= ConnectionType.scp_max_asymetry2
            possible_tunnel &= self.ratio_server_sent \
                               <= ConnectionType.tunnel_max_asymetry2

        # choose connection type (order of the conditions is important)
        if possible_shell:
            self.connection.connectionType = 'shell'
        elif possible_scp:
            self.connection.connectionType = 'scp'
        elif possible_tunnel:
            self.connection.connectionType = 'tunnel'
        else:
            self.logger.warning('Failed to find connection type')

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
        self.time_to_reply = []
        last_time = None
        for datagram in self.connection.datagrams:
            if not datagram.payloadLen:
                # no payload, skip
                continue
            if datagram.sentByClient:
                # may create a reply
                last_time = datagram.time
            else:
                if last_time is not None and datagram.RTT.total_seconds():
                    # a reply
                    self.time_to_reply.append(
                        (datagram.time - last_time).total_seconds() /
                        datagram.RTT.total_seconds()
                        )
                    last_time = None
