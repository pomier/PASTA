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


"""
Detection of stepping stones at the server side based on the paper
    Stepping Stone Detection at The Server Side
by Ruei-Min Lin, Yi-Chun Chou, and Kuan-Ta Chen
It is assumed that Nagle's algorithm is enabled at the client.
"""
import logging
from plugins import SingleConnectionAnalyser

class SteppingStoneDetectionServerSide(SingleConnectionAnalyser):

    """
    Detection of stepping stones at the server side based on the paper
        Stepping Stone Detection at The Server Side
    by Ruei-Min Lin, Yi-Chun Chou, and Kuan-Ta Chen
    It is assumed that Nagle's algorithm is enabled at the client.
    """

    IAT_RTT_DIFFERENT = 0.01
    CLOSE_ENOUGH = 0.5
    N_MOD_DIST = 0.98
    MIN_SIZE = 0.1

    IN_GROUP = 3

    def activate(self):
        """Activation of the plugin"""
        SingleConnectionAnalyser.activate(self)
        self.logger = logging.getLogger('SSDServerS')

    def analyse(self, connection):
        """Does all the computations"""
        self.connection = connection
        self.stepping_stone = False

        if self.connection.datagrams == None:
            raise RuntimeWarning("No datagram in the connection.")
        else:
            self.datagrams = [datagram for datagram in \
                              self.connection.datagrams if \
                              datagram.sentByClient and datagram.payloadLen]

            self.logger.debug('Starting computation for connect. #%d' \
                                                        % self.connection.nb)
            if len(self.connection.datagrams)>20:
                try:
                    self.stepping_stone = self.is_stepping_stone()
                    self.logger.debug('Stepping stone detected: %s' \
                                                % self.stepping_stone)
                except:
                    raise RuntimeWarning("Missing field in the connection\
                                                    (payload or RTT).")
            else:
                self.logger.debug('Not enough datagrams in connection')
                raise RuntimeWarning('Not enough datagrams in connection')

    def result_repr(self):
        """Returns the result of the computations as a string"""
        return 'Stepping stone detected (server-side): %s' \
                % (self.stepping_stone)

    def is_stepping_stone(self):
        """Is the connection part of a stepping stone chain?"""
        return self.compare_rtt_iat() or self.is_modally_distributed()

    def compare_rtt_iat(self):
        """
        Compares inter-arrival times between packets from client, and
        RTTserver->client. Returns True if both are very different, and False
        in the other case.
        """
        self.logger.debug('Computation of RTT & IAT similarity')
        # creation of the RTTs list.
        rtts = [datagram.RTT.total_seconds() for datagram in self.datagrams]
        rtts = rtts[1:]
        iats = []
        first = True
        last_datagram = None

        if len(rtts) < 20:
            self.logger.debug('Not enough useful datagrams to do the' \
                ' computation')
            raise RuntimeWarning('Not enough useful datagrams to do the' \
                                 ' computation')

        # creation of the IATs list.
        for datagram in self.connection.datagrams:
            if not datagram.payloadLen:
                continue # ignore packets without payload
            if not first and datagram.sentByClient:
                iats.append(\
                        (datagram.time - last_datagram.time).total_seconds())
                last_datagram = datagram
            if first and datagram.sentByClient:
                last_datagram = datagram
                first = False

        compt = 0.

        # for each value, if the value of IAT is close enough to the one of the
        # RTT, increment the value of compt.
        for i in range(len(rtts)):
            if rtts[i] != 0 and abs((rtts[i] - iats[i])/rtts[i]) \
                                                        <= self.CLOSE_ENOUGH:
                compt += 1

        self.logger.debug('Similarity between IATs & RTTs: %.2f%%' \
                  % (float(compt) / len(rtts) * 100))

        # returns True if IATs & RTTs are different enough.
        return compt / len(rtts) <= self.IAT_RTT_DIFFERENT

    def closest_group(self, payload, groups):
        """
        Returns the closest group for a certain payload.
        """
        closest = None
        for group in groups:
            if abs(group - payload) <= self.IN_GROUP and \
                    (closest is None or abs(group - payload) < closest):
                closest = group
        return closest

    def update_average_possible(self, closest, groups):
        """
        Checks if the value of the group can be updated (no superposition).
        """
        prov_average = sum(groups[closest]) / len(groups[closest])
        for group in groups:
            if abs(group - prov_average) <= self.IN_GROUP:
                return False
        return True

    def is_modally_distributed(self):
        """
        Checks if the distribution is n-modally distributed.
        """
        self.logger.debug('Checking if n-modulus distribution.')

        payloads = [datagram.payloadLen for datagram in self.datagrams]
        groups = {}
        for payload in payloads:
            closest = self.closest_group(payload, groups)
            if closest == None:
                groups[payload] = [payload]
            else:
                groups[closest].append(payload)
                if self.update_average_possible(closest, groups):
                    groups[sum(groups[closest]) / len(groups[closest])] = \
                        groups[closest]
                    del groups[closest]
        nb = 0
        for group in groups:
            if len(groups[group]) > len(payloads) * self.MIN_SIZE:
                nb += len(groups[group])

        self.logger.debug( 'n-modulus at %.2f%%' % (float(nb) / \
                                                len(payloads) * 100 ))

        return nb > self.N_MOD_DIST * len(payloads)
