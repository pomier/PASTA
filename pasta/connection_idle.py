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

"""Computes the idle time for a connection"""


import logging
from datetime import timedelta

class ConnectionIdle():
    """Computes the idle time for a connection"""

    # Configuration constant
    time_interval = timedelta(seconds=2)

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


if __name__ == '__main__':

    import unittest, sys

    if sys.version_info[:2] != (2, 7):
        sys.stderr.write('PASTA must be run with Python 2.7\n')
        sys.exit(1)

    class TestConnection(unittest.TestCase):
        pass # TODO: unit test(s) : useful in this case ?

    unittest.main()
