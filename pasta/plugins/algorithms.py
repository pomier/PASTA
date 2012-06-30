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

"""Finds the algorithms (most probably) used"""


from plugins import SingleConnectionAnalyser
import colors as C

class Algorithms(SingleConnectionAnalyser):
    """
    Finds the algorithms (most probably) used

    Uses: protocol.clientAlgos, protocol.serverAlgos
    """

    # We need these algorithms to determine best guesses
    # list from http://www.iana.org/assignments/ssh-parameters/ssh-parameters.xml
    KEX_ALGORITHMS = {
            # values are (requires_encryption, requires_signature)
            'diffie-hellman-group-exchange-sha1': ('TODO', 'TODO'), # TODO
            'diffie-hellman-group-exchange-sha256': ('TODO', 'TODO'), # TODO
            'diffie-hellman-group1-sha1': ('TODO', 'TODO'), # TODO
            'diffie-hellman-group14-sha1': ('TODO', 'TODO'), # TODO
            'ecdh-sha2-*': ('TODO', 'TODO'), # TODO
            'ecmqv-sha2': ('TODO', 'TODO'), # TODO
            'gss-group1-sha1-*': (False, False), # TODO
            'gss-group14-sha1-*': (False, False), # TODO
            'gss-gex-sha1-*': (False, False), # TODO
            'gss-*': (False, False), # TODO
            'rsa1024-sha1': (False, True), # TODO
            'rsa2048-sha256': (False, True) # TODO
            }
    SERVER_HOST_KEY_ALGORITHMS = {
            # values are (encryption_capable, signature_capable)
            'ssh-dss': ('TODO', True), # TODO
            'ssh-rsa': ('TODO', True), # TODO
            'spki-sign-rsa': ('TODO', True), # TODO
            'spki-sign-dss': ('TODO', True), # TODO
            'pgp-sign-rsa': ('TODO', True), # TODO
            'pgp-sign-dss': ('TODO', True), # TODO
            'null': (False, False),
            'ecdsa-sha2-*': ('TODO', True), # TODO
            'x509v3-ssh-dss': ('TODO', True), # TODO
            'x509v3-ssh-rsa': ('TODO', True), # TODO
            'x509v3-rsa2048-sha256': ('TODO', True), # TODO
            'x509v3-ecdsa-sha2-*': ('TODO', True) # TODO
            }

    def analyse(self, connection):
        """
        Finds the algos most probably used.

        We choose the first "guessed" as explained in RFC 4253 section 7.1
        """
        if connection.clientAlgos is None or connection.serverAlgos is None:
            raise RuntimeWarning("No algos found in connection")

        self.connection = connection
        kex_algo, shk_algo = self.determine_kex_and_server_host_key_algo()
        self.algos = {
                    'kex': kex_algo,
                    'server_host_key': shk_algo,
                    'encryption_c2s': self.determine_algo(\
                                    'encryption_algorithms_client_to_server'),
                    'encryption_s2c': self.determine_algo(\
                                    'encryption_algorithms_server_to_client'),
                    'mac_c2s': 
                        self.determine_algo('mac_algorithms_client_to_server'),
                    'mac_s2c':
                        self.determine_algo('mac_algorithms_server_to_client'),
                    'compression_c2s': self.determine_algo(\
                                    'compression_algorithms_client_to_server'),
                    'compression_s2c': self.determine_algo(\
                                    'compression_algorithms_server_to_client'),
                }

    def determine_kex_and_server_host_key_algo(self):
        """Determine the kex_algo and server_host_key_algo"""
        client_algos = self.connection.clientAlgos['kex_algorithms'].split(",")
        server_algos = self.connection.serverAlgos['kex_algorithms'].split(",")
        for algo in client_algos:
            # check if server supports algo
            if algo not in server_algos:
                continue
            # if algo not known, assume requires nothing
            cap_needed = (False, False)
            # if algo known, find what is required
            for known_algo in self.KEX_ALGORITHMS:
                if known_algo[-1] == '*':
                    if algo.startswith(known_algo[-1]) and '@' not in algo:
                        cap_needed = self.KEX_ALGORITHMS[known_algo]
                        break
                else:
                    if algo == known_algo:
                        cap_needed = self.KEX_ALGORITHMS[known_algo]
                        break
            # check that we can have an algo with required capabilities
            try:
                shk_algo = self.determine_server_host_key_algo(cap_needed)
            except StandardError:
                continue
            # return what is required and the choosen algo
            return (algo, shk_algo)
        return ('unknown', 'unknown')

    def determine_server_host_key_algo(self, cap_needed):
        """Determine the server_host_key_algo given the nedded capacities"""
        client_algos = self.connection.clientAlgos \
                ['server_host_key_algorithms'].split(",")
        server_algos = self.connection.serverAlgos \
                ['server_host_key_algorithms'].split(",")
        for algo in client_algos:
            # check if server supports algo
            if algo not in server_algos:
                continue
            # check if algo is known
            # if algo is not known, assume it has not any capabilities
            for known_algo in self.SERVER_HOST_KEY_ALGORITHMS:
                cap = self.SERVER_HOST_KEY_ALGORITHMS[known_algo]
                # check if this algo has the required capabilities
                if cap_needed[0] and not cap[0]:
                    continue
                if cap_needed[1] and not cap[1]:
                    continue
                # check if this is the corresponding algo
                if algo.startswith(known_algo[:-1]) and '@' not in algo:
                    return algo # algo found!
                elif algo == known_algo:
                    return algo # algo found!
        raise StandardError('No algorithm with required capabilities found')

    def determine_algo(self, field):
        """Determines the algorithm of the specified type"""
        client_algos = self.connection.clientAlgos[field].split(",")
        server_algos = self.connection.serverAlgos[field].split(",")
        for algo in client_algos:
            if algo in server_algos:
                return algo
        return 'unknown'

    @staticmethod
    def result_fields():
        """
        Return the fields of the analyse as a tuple of strings
        (same order as in result_repr)
        """
        return (
                'Key exchange algorithm',
                'Server host key algorithm',
                'Encryption algorithm (client to server)',
                'Encryption algorithm (server to client)',
                'MAC algorithm (client to server)',
                'MAC algorithm (server to client)',
                'Compression algorithm (client to server)',
                'Compression algorithm (server to client)'
                )

    @staticmethod
    def result_fields_table():
        """Set the fields that can be put in a client/server table"""
        return [(
                    'Encryption',
                    'Encryption algorithm (client to server)',
                    'Encryption algorithm (server to client)'
                ), (
                    'MAC',
                    'MAC algorithm (client to server)',
                    'MAC algorithm (server to client)'
                ), (
                    'Compression',
                    'Compression algorithm (client to server)',
                    'Compression algorithm (server to client)'
                )]

    def result_repr(self):
        """
        Return the result of the analyse as a tuple of strings
        (same order as in fields_repr)
        """
        return {
                'Key exchange algorithm': self.algos['kex'],
                'Server host key algorithm': self.algos['server_host_key'],
                'Encryption algorithm (client to server)': \
                    C.FBlu + self.algos['encryption_c2s'] + C.FRes,
                'Encryption algorithm (server to client)': \
                    C.FYel + self.algos['encryption_s2c'] + C.FRes,
                'MAC algorithm (client to server)': \
                    C.FBlu + self.algos['mac_c2s'] + C.FRes,
                'MAC algorithm (server to client)': \
                    C.FYel + self.algos['mac_s2c'] + C.FRes,
                'Compression algorithm (client to server)': \
                    C.FBlu + self.algos['compression_c2s'] + C.FRes,
                'Compression algorithm (server to client)': \
                    C.FYel + self.algos['compression_s2c'] + C.FRes
                }

# TODO: unit tests
