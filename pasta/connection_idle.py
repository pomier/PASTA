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
            # connection is empty anyway (avoid division by zero)
            return
        # starts to count idle times
        time_idle = timedelta() # cumul of the idle times
        datagrams_iterator = iter(self.connection.datagrams)
        last_datagram = datagrams_iterator.next() # first datagram
        for datagram in datagrams_iterator:
            diff_time = datagram.time - last_datagram.time
            if diff_time > ConnectionIdle.idle_rtt_threshold * datagram.RTT:
                time_idle += diff_time # add to the cumulated time
            last_datagram = datagram
        # save the idle time
        self.connection.idleTime = time_idle.total_seconds() \
            / self.connection.duration.total_seconds()
        # FIXME: consider idle at tcp or ssh level?
        # FIXME: results don't seems to be ok

# TODO: unit test(s)
