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
from datetime import timedelta

class ConnectionIdle():

    # Configuration constants
    idle_rtt_threshold = 5 # nb of RTTs for a packet to become idle

    def __init__(self, connection):
        self.connection = connection

    
    def compute(self):
        """Compute the idle time"""
        if not self.connection.duration.total_seconds():
            # connection is empty anyway
            return
        # starts to count idle times
        time_idle = timedelta() # cumul of the idle times
        last_datagram = self.connection.datagrams[0] # last datagram
        for datagram in self.connection.datagrams[1:]:
            diff_time = datagram.time - last_datagram.time
            if diff_time > ConnectionIdle.idle_rtt_threshold * datagram.RTT:
                time_idle += diff_time # add to the cumulated time
            last_datagram = datagram
        self.connection.idleTime = time_idle.total_seconds() \
            / self.connection.duration.total_seconds()

    
    def compute_old(self): # FIXME : previous version of the compute function.
        """Compute the idle time"""
        if not self.connection.duration.total_seconds():
            # connection is empty anyway
            return
        # starts to count idle times
        time_idle = timedelta() # cumul of the idle times
        last_datagram = None # last datagram sent by the server
        for datagram in self.connection.datagrams:
            if datagram.sentByClient:
                if last_datagram is not None:
                    # time since last datagram sent by the server
                    diff_time = datagram.time - last_datagram.time
                    if diff_time \
                            > ConnectionIdle.idle_rtt_threshold * datagram.RTT:
                        time_idle += diff_time # add to the cumulated time
                        last_datagram = None
            else:
                last_datagram = datagram # datagram sent by the server
        # save the idle time
        self.connection.idleTime = time_idle.total_seconds() \
                / self.connection.duration.total_seconds()
