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


# FIXME : complete doc and comments + clean code
# FIXME remove all print calls (move them to logging calls?)

"""
Detection of stepping stones at the server side.
Hypothesis that Nagle's algorithm is enabled at the client.
"""

from plugin import Plugin
#import matplotlib.pyplot as plt


class SteppingStoneDetectionServerSide(Plugin):
    
    # TODO: doc

    DESCRIPTION = '' # TODO

    def __init__(self, connections):
        Plugin.__init__(self, connections)
        self.is_stepping_stone = {}

    def compute(self):
        """Do all the computations"""
        for connection in self.connections:
            ssdssc = SteppingStoneDetectionServerSideConnection(connection)
            self.is_stepping_stone[connection] = ssdssc.is_stepping_stone()

    def result(self):
        """Return the result of the computations as a string"""
        # FIXME: result output
        s = 'Stepping stones detected (server-side connection method):'
        stepping_stones = [c.nb for c in self.connections if self.is_stepping_stone[c]]
        if stepping_stones:
            s += '\n    ' + ', '.join(stepping_stones)
        else:
            s += '\n    none'
        return s


class SteppingStoneDetectionServerSideConnection:
    """
    Detection of stepping stones...
    returns true if stepping stone, false in the other case
    """

    def __init__(self, connection):
        self.connection = connection
        self.datagrams = [datagram for datagram in self.connection.datagrams \
                          if datagram.sentByClient and datagram.payloadLen ]
        print "nb packets : " + str(len(self.datagrams))

    def is_stepping_stone(self):
        """Is the connection part of a stepping stone chain?"""
        return self.compare_RTT_IAT() or self.is_PS_modally_distributed()

    def compare_RTT_IAT(self):
        """
        compares inter-arrival times between packets from client, and
        RTTserver->client. Returns True if both are nearly equal, and False 
        in the other case.
        """
        # FIXME: these two values should be constants of the class
        percentage_similarity = 0.8
        percentage_close = 0.15
        RTTs = [datagram.RTT.total_seconds() for datagram in self.datagrams]
        RTTs = RTTs[1:]
        IATs = []
        first = True
        for datagram in self.connection.datagrams:
            if not datagram.payloadLen:
                continue # ignore packets without payload
            if not first and datagram.sentByClient :
                IATs.append(\
                        (datagram.time - last_datagram.time).total_seconds())
                last_datagram = datagram
            if first and datagram.sentByClient :
                last_datagram = datagram
                first = False
        
        compt = 0.
        
        for i in range(len(RTTs)) :
            if (abs(RTTs[i] - IATs[i]) / RTTs[i]) <= percentage_close:
                compt += 1
        print "similarity between IATs & RTTs: %.2f%%" \
                % (float(compt) / len(RTTs) * 100) 
        if compt / len(RTTs) >= percentage_similarity:
            return True
        #plt.axis([0,len(IATs),0,0.4])
        
        #plt.plot(IATs,"ro")
        #plt.plot(RTTs,"bo")
        
        #plt.show()
        
        
        return False
    
    def closest_group(self, payload, groups):
        closest = None
        for group in groups:
            # FIXME: what does the 5 value comes from? if it comes from
            # some experiments, just put it as a constants of the class
            if abs(group - payload) < 5 and \
                    (closest is None or abs(group - payload) < closest):
                closest = group
        return closest
    
    def update_average_possible(self, closest, groups):
        prov_average = sum(groups[closest]) / len(groups[closest])
        for group in groups:
            if abs(group - prov_average) < 5:
                return False
        return True
    
    
    def is_PS_modally_distributed(self):
        payloads = [datagram.payloadLen for datagram in self.datagrams]
        
        groups = {}
        
        for payload in payloads:
            closest = self.closest_group(payload, groups)
            if closest == None:
                groups[payload] = [payload]
            else :
                groups[closest].append(payload)
                if self.update_average_possible(closest, groups):
                    groups[sum(groups[closest]) / len(groups[closest])] = \
                        groups[closest]
                    del groups[closest]
        #print groups
        nb = 0
        for group in groups :
            # FIXME: what does the 10 value comes from? if it comes from
            # some experiments, just put it as a constants of the class
            if 10 * len(groups[group]) > len(payloads):
                nb += len(groups[group])
        print "n-modulus at %.2f%%" % (float(nb) / len(payloads) * 100)
        
        if nb > 0.98 * len(payloads):
            return True
        
        #plt.axis([0,len(payloads),0,200])
        
        #plt.plot(payloads,"ro")
        #plt.show()
        
        return False


if __name__ == '__main__':
    pass
    #print SteppingStoneDetectionServerSide().compute()
