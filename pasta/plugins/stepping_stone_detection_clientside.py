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
#
#
# Severals articles are used in this file :
# [1] Matching TCP Packets and Its Application to the Detection of Long
# Connection Chains on the Internet,
# by Jianhua Yang and Shou-Hsuan Stephen Huang
# [2] A Real-Time Algorithm to Detect Long Connection Chains of Interactive
# Terminal Sessions, by Jianhua Yang and Shou-Hsuan Stephen Huang

import logging
from plugins import SingleConnectionAnalyser
#import matplotlib.pyplot as plt

# FIXME: implement the plugin-related stuff

class SteppingStoneDetectionClientSide(SingleConnectionAnalyser):
    """
    Detection of stepping stones at the client side.
    Gives the number of following machines in the stepping stones chain.
    Based on the paper
        Matching TCP Packets and Its Application to the Detection of Long
        Connection Chains on the Internet
    by Jianhua Yang and Shou-Hsuan Stephen Huang
    """

    def activate(self):
        """Activation of the plugin"""
        SingleConnectionAnalyser.activate(self)
        self.logger = logging.getLogger('SSDClientS')
        self.hosts_number = 0

    def analyse(self, connection):
        """Do all the computations"""
        # TODO
        self.logger.debug('Starting analyse #%d' % (connection.nb))
        (time, rtt) = self.compute_matching(connection)
        averaged = self.clean(rtt)
        self.hosts_number = self.count_jumps(averaged)
        # Low pass filter
        #kernel = [1]
        #low_pass = self.convolve(rtt, kernel)
        #low_pass = averaged
        #plt.plot(range(len(low_pass)), low_pass)
        #plt.show()

    @staticmethod
    def result_fields():
        """
        Return the fields of the analyse as a tuple of strings
        (same order as in result_repr)
        """
        return ('Stepping stone detected (client-side)',)

    def result_repr(self):
        """Return the result of the computations as a string"""
        return {'Stepping stone detected (client-side)':
            '%d hosts' % (self.hosts_number)}

    def compute_matching(self, connection):
        """Match the right packets to get RTT
        Based on heuristicalgorithm in [1]
        """
        tg_threshold = 0.5
        previousSendPacket = None
        sendQ = []
        rtt = []
        time = []
        time0 = None

        for p in connection.datagrams:
            if not time0:
                time0 = p.time
            if p.sent_by_client and p.payload_len > 0:
                # This is a "Send" packet
                if previousSendPacket and \
                        (p.time - previousSendPacket.time).total_seconds() > \
                            tg_threshold:
                    # Reset the queue
                    sendQ = []
                else:
                    sendQ.append(p)
                previousSendPacket = p
            elif not p.sent_by_client and p.payload_len > 0:
                # This is a "Echo" packet sent by the last server in chain
                q = sendQ.pop(0) if len(sendQ) else None
                if q and q.ack <= p.seq_nb and q.seq_nb < p.ack:
                    # Packets p and q are matched
                    if (p.time - q.time).total_seconds() < 1:
                        rtt.append((p.time - q.time).total_seconds() * 2)
                        time.append((p.time - time0).total_seconds())

        return (time, rtt)

    def clean(self, curve):
        result = []
        # Get rid of the 10 first packets (false results)
        i = 10
        for i in range(20, len(curve) - 2):
            mean = sum(curve[i-2:i+3])/5
            if abs(curve[i] - mean) * 100 < 5*curve[i]:
                result.append(curve[i])

        return result

    def count_jumps(self, rtt):
        """
        Count jumps in roundtrip time, representing the number of hosts in the
        connection chain.
        Based on algorithm 2 in [2]
        """

        jumps = 1
        max_jumps = 1

        if len(rtt) < 6:
            return jumps

        i = 5
        while i < len(rtt)-1:
            minLeft = min([rtt[i-5], rtt[i-4], rtt[i-3]])
            maxLeft = max([rtt[i-5], rtt[i-4], rtt[i-3]])
            minRight = min([rtt[i-2], rtt[i-1], rtt[i]])
            maxRight = max([rtt[i-2], rtt[i-1], rtt[i]])
            diff = minLeft - minRight
            if (minLeft - maxRight) * 100 > 20*maxRight and jumps > 1:
                jumps -= 1
                i += 5
            elif (minRight - maxLeft) * 100 > 20*maxLeft:
                jumps += 1
                i += 5
                if jumps > max_jumps:
                    max_jumps = jumps
            i += 1
        return max_jumps
                
    def compute_threshold(self, rtt):
        number = 0
        total = 0
        for i in range(1,len(rtt)):
            if rtt[1] - rtt[1-1] > 0:
                total += (rtt[1] - rtt[1-1])
                number += 1
        if number == 0:
            return 0
        else:
            return total/number
