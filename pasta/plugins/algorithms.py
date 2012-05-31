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


from plugins import SingleConnectionAnalyser
import colors as C

class Algorithms(SingleConnectionAnalyser):
    """
    Find the algorithms (most probably) used

    Uses: protocol.clientAlgos, protocol.serverAlgos
    """

    def analyse(self, connection):
        """
        Find the algos most probalby used
        
        We choose the first "guest" as explained in RFC 4243 §7.1
        """
        if connection.clientAlgos is None or connection.serverAlgos is None:
            raise ValueError("No algos found in connection")
        # TODO!!!
        self.algos = {
                    'kex': 'unknown',
                    'server_host_key': 'unknown',
                    'encryption_c2s': 'unknown',
                    'encryption_s2c': 'unknown',
                    'mac_c2s': 'unknown',
                    'mac_s2c': 'unknown',
                    'compression_c2s': 'unknown',
                    'compression_s2c': 'unknown',
                }


    def result_repr(self):
        """Return the result of the analyse as a string"""
        return (
                    'Key exchange algorithm: %s\n'
                    'Server host key algorithm: %s\n'
                    'Encryption algorithms: C>S: %s, S>C: %s\n'
                    'MAC algorithms: C>S: %s, S>C: %s\n'
                    'Compression algorithms: C>S: %s, S>C: %s'
                ) % (
                    self.algos['kex'],
                    self.algos['server_host_key'],
                    C.FBlu + self.algos['encryption_c2s'] + C.FRes,
                    C.FYel + self.algos['encryption_s2c'] + C.FRes,
                    C.FBlu + self.algos['mac_c2s'] + C.FRes,
                    C.FYel + self.algos['mac_s2c'] + C.FRes,
                    C.FBlu + self.algos['compression_c2s'] + C.FRes,
                    C.FYel + self.algos['compression_s2c'] + C.FRes
                )

if __name__ == '__main__':
    pass # TODO: unittests
