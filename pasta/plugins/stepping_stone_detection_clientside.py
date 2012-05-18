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


from plugin import PluginConnectionsAnalyser

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
        self.is_stepping_stone = {}

    def analyse(self):
        """Do all the computations"""
        # TODO
        for connection in self.connections:
            continue

    def result(self):
        """Return the result of the computations as a string"""
        # TODO

