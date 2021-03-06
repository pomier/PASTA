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
Detection of stepping stones based on the paper
    Detecting Stepping Stones
by Yin Zhang and Vern Paxson
"""


from plugins import InterConnectionsAnalyser
from datetime import timedelta

class SteppingStoneDetectionOnOff(InterConnectionsAnalyser):
    """
    Detection of stepping stones based on the paper
        Detecting Stepping Stones
    by Yin Zhang and Vern Paxson
    """

    # Control parameters (names from the paper), values are choosen from 5.6
    # for the initial computations
    TIDLE = timedelta(seconds = 0.5)
    DELTA = timedelta(seconds = 0.016)
    # for the first restriction of matches
    GAMMA = 0.45
    # for the second restriction of matches
    MINCSC = 2
    GAMMAPRIME = 0.02

    def analyse(self, connections):
        """Analyse the connections"""
        # Init
        self.connections = connections
        self.off = {}
        self.correlated = {}
        self.consecutive = {}
        self.matches = [] # list of the possible couples of connections
        # i.e. (i, j) with i < j were i and j are the connection.nb values
        for c1 in self.connections:
            iterator = iter(self.connections)
            while iterator.next() != c1:
                pass
            for c2 in iterator:
                self.matches.append((c1, c2))
        # Initial computations
        self.compute_off()
        self.compute_coincidences()
        # First restriction of matches
        self.first_check()
        # Second restriction of matches
        self.second_check()
        # check if we found any matches
        if not self.matches:
            raise RuntimeWarning("No match found")

    def compute_off(self):
        """Find the off periods for each connection"""
        for connection in self.connections:
            self.off[connection] = []
            iterator = iter(connection.datagrams)
            last_time = iterator.next().time
            for datagram in iterator:
                if not datagram.payload_len:
                    continue # consider only datagrams with payload
                if datagram.time - last_time < self.TIDLE:
                    self.off[connection].append(datagram.time)
                last_time = datagram.time

    def compute_coincidences(self):
        """Compute the correlations and number of consecutive coincidences"""
        for (c1, c2) in self.matches:
            consecutives = []
            consecutive = 0
            correlated = 0
            off1 = iter(self.off[c1])
            off2 = iter(self.off[c2])
            end1 = off1.next()
            end2 = off2.next()
            while True:
                if end1 - end2 < self.DELTA and end2 - end1 < self.DELTA:
                    consecutive += 1
                    correlated += 1
                else:
                    consecutives.append(consecutive)
                    consecutive = 0
                try:
                    if end1 > end2:
                        end2 = off2.next()
                    else:
                        end1 = off1.next()
                except StopIteration:
                    break
            consecutives.append(consecutive)
            self.correlated[c1, c2] = correlated
            self.consecutive[c1, c2] = max(consecutives)

    def first_check(self):
        """4.2 Timing correlation when OFF periods end"""
        self.matches = [(c1, c2)
                for (c1, c2) in self.matches
                if self.correlated[c1, c2] >= self.GAMMA *
                    min(len(self.off[c1]), len(self.off[c2]))
                ]

    def second_check(self):
        """4.3 Refinements"""
        self.matches = [(c1, c2)
                for (c1, c2) in self.matches
                if self.consecutive[c1, c2] >= self.MINCSC
                ]
        self.matches = [(c1, c2)
                for (c1, c2) in self.matches
                if self.consecutive[c1, c2] >= self.GAMMAPRIME *
                    min(len(self.off[c1]), len(self.off[c2]))
                ]

    def result_repr(self):
        """Return the result of the analyse as a string"""
        s = 'Stepping stone links detected (on-off method):'
        for c1, c2 in self.matches:
            s += '\n    %d <-> %d' % (c1.nb, c2.nb)
        return s
