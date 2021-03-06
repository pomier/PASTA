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


import logging, unittest, random
from datetime import timedelta, datetime
from plugins import SingleConnectionAnalyser

class ConnectionIdle(SingleConnectionAnalyser):
    """
    Computes the idle time for a connection

    Uses: payload_len, time
    """

    # Configuration constant
    time_interval = timedelta(seconds=2)

    def activate(self):
        """Activation of the plugin"""
        SingleConnectionAnalyser.activate(self)
        self.logger = logging.getLogger('ConnIdle')

    def analyse(self, connection):
        """
        Computes the idle time

        Simply cuts the duration of the connection in intervals of fixed length
        Idle time is the percentage of intervals with no packets with payload
        """
        self.connection = connection
        self.logger.info('Starting computation')
        if not self.connection.duration.total_seconds():
            # connection is empty anyway (avoid division by zero)
            self.logger.warning('Connection is empty')
            return
        intervals_total = intervals_idle = 0 # counters
        position = self.connection.start_time # left limit of the interval
        for datagram in self.connection.datagrams:
            if not datagram.payload_len:
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
        self.idle_time = intervals_idle / float(intervals_total)

    @staticmethod
    def result_fields():
        """
        Return the fields of the analyse as a tuple of strings
        (same order as in result_repr)
        """
        return ('Idle time',)

    def result_repr(self):
        """
        Return the result of the analyse as a tuple of strings
        (same order as in fields_repr)
        """
        return {'Idle time': '%.1f%%' % (self.idle_time * 100)}


class TestConnectionIdle(unittest.TestCase):
    """Unit tests for ConnectionIdle"""

    class FakeDatagram():
        def __init__(self, time):
            self.payload_len = random.choice((0, 32, 42, 1024))
            self.time = time

    class FakeConnection():
        def __init__(self):
            self.datagrams = []
            self.duration = timedelta(seconds=random.randint(10, 1000))
            self.start_time = datetime.now()
            self.nb = random.randint(0, 100000)

        def fake_random(self):
            """Fake a random connection"""
            time = self.start_time
            for _ in xrange(1000):
                time += timedelta(microseconds=random.randint(100000, 9000000))
                self.datagrams.append(TestConnectionIdle.FakeDatagram(time))

    def setUp(self):
        """Done before every test"""
        self.connection = TestConnectionIdle.FakeConnection()
        self.connection.fake_random()
        self.connection_idle = ConnectionIdle()
        self.connection_idle.activate()

    def tearDown(self):
        """Done after every test"""
        self.connection_idle.deactivate()

    def test_idle_range(self):
        """Check that 0 <= idle <= 1"""
        self.connection_idle.analyse(self.connection)
        self.assertGreaterEqual(self.connection_idle.idle_time, 0)
        self.assertLessEqual(self.connection_idle.idle_time, 1)

    # there is not much to test anyway, since the idle time is subjective


if __name__ == '__main__':
    import sys
    # check Python version
    if sys.version_info[:2] != (2, 7):
        sys.stderr.write('PASTA must be run with Python 2.7\n')
        sys.exit(1)
    # make sure we have the same test cases each time
    random.seed(42)
    # run the unit tests
    unittest.main()
