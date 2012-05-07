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


# FIXME : complete doc and comments+clean code
"""
Detection of stepping stones at the server side.
Hypothesis that Nagle's algorithm is enabled at the client.
"""

from datetime import timedelta
import matplotlib.pyplot as plt
import numpy as np
import logging 

class SteppingStoneDetectionServerSide:
    """
    Detection of stepping stones...
    returns true if stepping stone, false in the other case
    """
    
    def __init__(self,connection):
        self.connection = connection
        self.datagrams = [datagram for datagram in self.connection.datagrams \
                          if datagram.sentByClient and datagram.payloadLen ]
        print "nb packets : "+str(len(self.datagrams))
    
    def compute(self):
        if self.compare_RTT_IAT():
            #stepping stone detected
            return True
        else:
            if self.is_PS_modally_distributed():
                #stepping stone detected
                return True
            else:
                #no stepping stone detected
                return False
    
    def compare_RTT_IAT(self):
        """
        compares inter-arrival times between packets from client, and
        RTTserver->client. Returns True if both are nearly equal, and False 
        in the other case.
        """
        percentage_similarity = 0.8
        percentage_close = 0.15
        RTTs = [datagram.RTT.total_seconds() for datagram in self.datagrams]
        RTTs = RTTs[1:len(RTTs)]
        IATs=[]
        first = True
        for datagram in self.connection.datagrams:
            if not datagram.payloadLen:
                # idle time at ssh level: ignore packets without payload
                continue
            if not first and datagram.sentByClient :
                IATs.append((datagram.time - last_datagram.time).total_seconds())
                last_datagram = datagram
            if first and datagram.sentByClient :
                last_datagram = datagram
                first = False
        
        compt = 0.
        
        for i in range(len(RTTs)) :
            if (abs(RTTs[i]-IATs[i])/RTTs[i]) <= percentage_close:
                compt+=1
        print "similarity between IATs & RTTs: "+str(compt/len(RTTs)*100)+"%"
        if compt/len(RTTs)>= percentage_similarity :
            return True
        #plt.axis([0,len(IATs),0,0.4])
        
        #plt.plot(IATs,"ro")
        #plt.plot(RTTs,"bo")
        
        #plt.show()
        
        
        return False
    
    def closest_group(self, payload, groups):
        closest = 10000
        for group in groups:
            if abs(group - payload) < 5 and abs(group - payload) < closest:
                closest = group
        if closest == 10000 : return None
        return closest
    
    def update_average_possible(self,closest,groups):
        prov_average = sum(groups[closest])/len(groups[closest])
        for group in groups:
            if abs(group - prov_average)<5:
                return False
        return True
    
    
    def is_PS_modally_distributed(self):
        payloads = [datagram.payloadLen for datagram in self.datagrams]
        
        groups = {}
        
        for payload in payloads:
            closest = self.closest_group(payload, groups)
            if closest == None:
                groups[payload]=[payload]
            else :
                groups[closest].append(payload)
                if self.update_average_possible(closest,groups):
                    groups[sum(groups[closest])/len(groups[closest])] = \
                        groups[closest]
                    del groups[closest]
        #print groups
        nb = 0.
        for group in groups :
            if len(groups[group])*1.0/len(payloads) > 0.1 :
                nb += len(groups[group])
        print "n-modulus at "+str(nb/len(payloads)*100)+"%"
        
        if nb/len(payloads) > 0.98 : 
            return True
        
        #plt.axis([0,len(payloads),0,200])
        
        #plt.plot(payloads,"ro")
        #plt.show()
        
        return False


if __name__ == '__main__':
    pass
#test = SteppingStoneDetectionServerSide()
#print test.compute()