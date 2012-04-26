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



import logging
from datetime import timedelta

class ConnectionIdle():
    """ Computes the idle time for a connection """

    # Configuration constants
    # FIXME which one are usefull
    idle_rtt_thld = 5 # nb of RTTs for a packet to become idle
    idle_same_origin_thld = timedelta(seconds=0.5) # time between two packets \
                                        # with the same origin to become idle.

    time_interval = timedelta(seconds=2) # seconds

    def __init__(self, connection):
        self.connection = connection
        self.logger = logging.getLogger('Conn%dIdle' % connection.nb)

    def compute(self):
        """
        Compute the idle time

        Simply cut the duration of the connection in intervals of fixed length
        Idle time is the percentage of intervals with no packets with payload
        """
        self.logger.info('Starting computation')
        if not self.connection.duration.total_seconds():
            # connection is empty anyway (avoid division by zero)
            self.logger.warning('Connection is empty')
            return
        intervals_total = intervals_idle = 0 # counters
        position = self.connection.startTime # left limit of the interval
        for datagram in self.connection.datagrams:
            if not datagram.payloadLen:
                # idle time at ssh level: ignore packets without payload
                continue
            if datagram.time < position:
                continue # already got one packet in the interval
            while datagram.time >= position:
                # this interval is idle, move to the next one
                intervals_idle += 1
                intervals_total += 1
                position += self.time_interval
            # in fact, the last one was not idle but busy
            intervals_idle -= 1
            self.logger.debug('Busy interval: %s - %s' % \
                    (position, position + self.time_interval))
        self.logger.debug('Idle intervals: %d/%d' % \
                (intervals_idle, intervals_total))
        self.connection.idleTime = intervals_idle / float(intervals_total)


    def compute_1(self):
        """Compute the idle time: 1rst method"""
        self.logger.info('Starting computation')

        if not self.connection.duration.total_seconds():
            # connection is empty anyway (avoid division by zero)
            self.logger.warning('Connection is empty')
            return
        # starts to count idle times
        time_idle = timedelta() # cumul of the idle times
        datagrams_iterator = iter(self.connection.datagrams)
        first_datagram = datagrams_iterator.next() # first datagram
        lastC_time = lastS_time = first_datagram.time
        lastC_RTT = lastS_RTT = first_datagram.RTT
        for datagram in datagrams_iterator:
            if not datagram.payloadLen:
                continue
            diff_timeC = datagram.time - lastC_time
            diff_timeS = datagram.time - lastS_time
            if diff_timeS > ConnectionIdle.idle_rtt_thld * lastS_RTT and \
                    diff_timeC > ConnectionIdle.idle_rtt_thld * lastC_RTT:
                time_idle += min(diff_timeC, diff_timeS) # add to cumulated time

            if datagram.sentByClient:
                lastC_RTT = datagram.RTT
                lastC_time = datagram.time
            else:
                lastS_RTT = datagram.RTT
                lastS_time = datagram.time
        # save the idle time
        self.connection.idleTime = time_idle.total_seconds() \
            / self.connection.duration.total_seconds()
        self.logger.info('Computations finished: idle is %.1f%%', \
                                            self.connection.idleTime * 100)
        # FIXME: consider case where no paquet from one side hasn't been sent \
        # for a while : need to "refresh" value ?

                
    def compute2(self):
        """Compute the idle time: 2nd method"""
        self.logger.info('Starting computation')

        if not self.connection.duration.total_seconds():
            # connection is empty anyway (avoid division by zero)
            self.logger.warning('Connection is empty')
            return
        # starts to count idle times
        time_idle = timedelta() # cumul of the idle times
        datagrams_iterator = iter(self.connection.datagrams)
        last_datagram = datagrams_iterator.next() # first datagram

        for datagram in datagrams_iterator:
            if not datagram.payloadLen:
                # idle time at ssh level: ignore packets without payload
                continue
            diff_time = datagram.time - last_datagram.time
            if datagram.sentByClient != last_datagram.sentByClient:
                # if there is a packet from the server followed by one of
                # the client, or the inverse.
                if diff_time > \
                    ConnectionIdle.idle_rtt_thld * last_datagram.RTT:
                    time_idle += diff_time
            else : # the case where two following packets have the same origin.
                if diff_time > ConnectionIdle.idle_same_origin_thld:
                    time_idle += diff_time
            last_datagram = datagram

        self.connection.idleTime = time_idle.total_seconds() \
            / self.connection.duration.total_seconds()
        self.logger.info('Computations finished: idle is %.1f%%', \
                                            self.connection.idleTime * 100)

# FIXME: we need to choose a method (or to do an average of the two ?)

if __name__ == '__main__':

    import unittest, sys

    if sys.version_info[:2] != (2, 7):
        sys.stderr.write('PASTA must be run with Python 2.7\n')
        sys.exit(1)

    class TestConnection(unittest.TestCase):
        pass # TODO: unit test(s) : useful in this case ?

    unittest.main()
