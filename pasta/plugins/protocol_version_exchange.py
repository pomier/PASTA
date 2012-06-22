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

"""Display the protocol version used by client and server"""


import unittest, random
from plugins import SingleConnectionAnalyser
import colors as C

class ProtocolVersionExchange(SingleConnectionAnalyser):
    """
    Display the protocol version used by client and server

    Uses: protocol.clientProtocol, protocol.serverProtocol
    """

    def analyse(self, connection):
        """Find the protocols anounced"""
        if connection.clientProtocol is None \
                and connection.serverProtocol is None:
            raise RuntimeWarning("No protocol exchange found in connection")
        self.client_protocol = self.separate(connection.clientProtocol)
        self.server_protocol = self.separate(connection.serverProtocol)

    def separate(self, protocol):
        """Separate the different parts from a protocol field"""
        if protocol is None:
            return None
        # see RFC 4253 part 4.2
        protocol = protocol.strip(' \x0a\x0d') # remove useless chars
        protocol = protocol.split(' ', 1)
        (_, ssh_version, soft_version) = protocol[0].split('-', 3)
        comment = None if len(protocol) == 1 else protocol[1]
        return {'ssh_version': ssh_version,
                'software_version': soft_version,
                'comment': comment}

    def protocol_repr(self, protocol, color):
        """Format the protocol for printing"""
        s = 'ssh version %s, software version %s' % (
                color + protocol['ssh_version'] + C.FRes,
                color + protocol['software_version'] + C.FRes
                )
        if protocol['comment'] is not None:
            s += ', comment: %s' % (color + protocol['comment'] + C.FRes)
        return s

    @staticmethod
    def result_fields():
        """
        Return the fields of the analyse as a tuple of strings
        (same order as in result_repr)
        """
        '''
        return ('Client protocol', 'Server protocol')
        '''
        return (
                'Client SSH version',
                'Server SSH version',
                'Client software version',
                'Server software version',
                'Client protocol comment',
                'Server protocol comment'
               )

    def result_repr(self):
        """
        Return the result of the analyse as a tuple of strings
        (same order as in fields_repr)
        """
        '''
        return {'Client protocol': self.protocol_repr(self.client_protocol, C.FBlu),
                'Server protocol': self.protocol_repr(self.server_protocol, C.FYel)}
        '''
        return {
                'Client SSH version': \
                    C.FBlu + self.client_protocol['ssh_version'] + C.FRes,
                'Server SSH version': \
                    C.FYel + self.server_protocol['ssh_version'] + C.FRes,
                'Client software version': \
                    C.FBlu + self.client_protocol['software_version'] + C.FRes,
                'Server software version': \
                    C.FYel + self.server_protocol['software_version'] + C.FRes,
                'Client protocol comment': None \
                        if self.client_protocol['comment'] is None \
                        else C.FBlu + self.client_protocol['comment'] +  C.FRes,
                'Server protocol comment': None \
                        if self.server_protocol['comment'] is None \
                        else C.FBlu + self.server_protocol['comment'] +  C.FRes
               }


class TestProtocolVersionExchange(unittest.TestCase):
    """Unit tests for ProtocolVersionExchange"""

    class FakeConnection():
        def setProtocols(self, client, server):
            self.clientProtocol = '%s\x0a\x0d' % client
            self.serverProtocol = '%s\x0a\x0d' % server

    def setUp(self):
        """Done before every test"""
        self.connection = TestProtocolVersionExchange.FakeConnection()
        self.connection_pve = ProtocolVersionExchange()
        self.connection_pve.activate()

    def tearDown(self):
        """Done after every test"""
        self.connection_pve.deactivate()

    def test_no_comment(self):
        """Protocols version without comments"""
        self.connection.setProtocols('SSH-2.0-OpenSSH_5.2',
                'SSH-2.0-OpenSSH_5.3')
        self.connection_pve.analyse(self.connection)
        self.assertEqual(self.connection_pve.client_protocol, {
            'ssh_version': '2.0',
            'software_version': 'OpenSSH_5.2',
            'comment': None
            })
        self.assertEqual(self.connection_pve.server_protocol, {
            'ssh_version': '2.0',
            'software_version': 'OpenSSH_5.3',
            'comment': None
            })

    def test_no_comment_space(self):
        """Protocols version without comments but a space at the end"""
        self.connection.setProtocols('SSH-2.0-OpenSSH_5.2 ',
                'SSH-2.0-OpenSSH_5.3 ')
        self.connection_pve.analyse(self.connection)
        self.assertEqual(self.connection_pve.client_protocol, {
            'ssh_version': '2.0',
            'software_version': 'OpenSSH_5.2',
            'comment': None
            })
        self.assertEqual(self.connection_pve.server_protocol, {
            'ssh_version': '2.0',
            'software_version': 'OpenSSH_5.3',
            'comment': None
            })

    def test_comment(self):
        """Protocols version with comments"""
        self.connection.setProtocols('SSH-2.0-OpenSSH_5.2 Debian-4',
                'SSH-2.0-OpenSSH_5.3 Trisquel')
        self.connection_pve.analyse(self.connection)
        self.assertEqual(self.connection_pve.client_protocol, {
            'ssh_version': '2.0',
            'software_version': 'OpenSSH_5.2',
            'comment': 'Debian-4'
            })
        self.assertEqual(self.connection_pve.server_protocol, {
            'ssh_version': '2.0',
            'software_version': 'OpenSSH_5.3',
            'comment': 'Trisquel'
            })

    def test_failback(self):
        """Protocols version 1.99 with comments"""
        self.connection.setProtocols('SSH-1.99-OpenSSH_5.2 Debian-4',
                'SSH-1.99-OpenSSH_5.3 Trisquel')
        self.connection_pve.analyse(self.connection)
        self.assertEqual(self.connection_pve.client_protocol, {
            'ssh_version': '1.99',
            'software_version': 'OpenSSH_5.2',
            'comment': 'Debian-4'
            })
        self.assertEqual(self.connection_pve.server_protocol, {
            'ssh_version': '1.99',
            'software_version': 'OpenSSH_5.3',
            'comment': 'Trisquel'
            })


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
