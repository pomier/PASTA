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

from plugin import PluginConnectionsAnalyser
#import matplotlib.pyplot as plt

class SteppingStoneDetectionClientSide(PluginConnectionsAnalyser):
    """
    Detection of stepping stones at the client side.
    Gives the number of following machines in the stepping stones chain.
    Based on the paper
        Matching TCP Packets and Its Application to the Detection of Long
        Connection Chains on the Internet
    by Jianhua Yang and Shou-Hsuan Stephen Huang
    """

    def load_connections(self, connections):
        self.connections = connections
        self.hosts = []

    def analyse(self):
        """Do all the computations"""
        # TODO
        for connection in self.connections:
            RTT = self.compute_matching(connection)
            self.hosts.append((connection, self.count_jumps(RTT)))
            # Low pass filter
#            kernel = [1]
#            low_pass = self.convolve(RTT, kernel)
#            low_pass = RTT
#            plt.plot(range(len(low_pass)), low_pass)
#        plt.show()

    def result(self):
        """Return the result of the computations as a string"""
        # TODO
        s = 'Stepping stone chains detected (client method):\n'
        for r in self.hosts:
            s += "#%d : Chain of %d hosts detected\n" % (r[0].nb+1, r[1])
        return s

    def compute_matching(self, connection):
        """Match the right packets to get RTT
        Based on heuristicalgorithm in [1]
        """
        tg_threshold = 0.5
        previousSendPacket = None
        sendQ = []
        RTT = []
        time0 = None

        for p in connection.datagrams:
            if not time0:
                time0 = p.time
            if p.sentByClient and p.payloadLen > 0:
                # This is a "Send" packet
                if previousSendPacket and \
                        (p.time - previousSendPacket.time).total_seconds() > \
                            tg_threshold:
                    # Reset the queue
                    sendQ = []
                else:
                    sendQ.append(p)
                previousSendPacket = p
            elif not p.sentByClient and p.payloadLen > 0:
                # This is a "Echo" packet sent by the last server in chain
                q = sendQ.pop(0) if len(sendQ) else None
                if q and q.ack <= p.seqNb and q.seqNb < p.ack:
                    # Packets p and q are matched
                    if (p.time - q.time).total_seconds() < 0.5:
                        RTT.append((p.time - q.time).total_seconds() * 2)

        return RTT

#    def clean(self, curve):
#        result = []
#        # Get rid of the 10 first packets (false results)
#        i = 10
#        while i < len(curve):
#            values = []
#            if i+10 <= len(curve):
#                values = curve[i:i+10]
#                values.sort()
#                median_value = values[len(values)/2]
#                for j in range(10):
#                    result.append(median_value)
#                result.append(median_value)
#            i += 10
#        for i in range(len(curve)):
#            total = 0
#            if i > 1:
#                total += curve[i-2]
#            if i < len(curve) - 2:
#                total += curve[i+2]
#            if curve[i] < total:
#                result.append(curve[i])
#
#        return result
#
#    def convolve(self, curve, kernel):
#        if len(kernel) % 2 == 0:
#            return []
#
#        result = []
#        middle = (len(kernel) - 1) / 2
#        for i in range(len(curve)):
#            total = 0
#            for j in range(len(kernel)):
#                if i+j-middle in range(len(curve)):
#                    total = total + kernel[j]*curve[i+j-middle]
#            result.append(total / sum(kernel))
#
#        return result

    def count_jumps(self, rtt):
        """
        Count jumps in roundtrip time, representing the number of hosts in the
        connection chain.
        Based on algorithm 2 in [2]
        """

        jumps = 0
        max_jumps = 0

        if len(rtt) < 6:
            return jumps

        # Threshold = average of values in array rtt
        threshold = self.compute_threshold(rtt)
#        print "Threshold %f" % (threshold)
        up = True

        for i in range(5, len(rtt)-1):
            minLeft = min([rtt[i-5], rtt[i-4], rtt[i-3]])
            minRight = min([rtt[i-2], rtt[i-1], rtt[i]])
            diff = minLeft - minRight
            if diff > 0:
                up = True
            else:
                up = False
                diff *= -1
            if diff > threshold:
                if up:
                    jumps += 1
                    if jumps > max_jumps:
                        max_jumps = jumps
                elif jumps > 0:
                    jumps -= 1
        return max_jumps
                
    def compute_threshold(self, rtt):
        number = 0
        total = 0
        for i in range(1,len(rtt)):
            if rtt[1] - rtt[1-1] > 0:
                total += (rtt[1] - rtt[1-1])
                number += 1
        return total/number

