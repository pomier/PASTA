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
Connections (+RTT computations) and datagrams structures
"""


import logging, unittest, random
from datetime import datetime, timedelta
import colors as C
try:
    from texttable import Texttable
except ImportError:
    Texttable = None

def str_td(td, short=False):
    """Better representation of a timedelta instance"""
    days = td.days
    hours = td.seconds / 3600
    mins = (td.seconds % 3600) / 60
    secs = td.seconds % 60
    s = ''
    if days:
        if short:
            s += 'about '
            if hours >= 12:
                days += 1
        s += '%s day%s' % (
             ('one', '') if days == 1
             else ('%d' % days, 's'))
        if short:
            return s
        s += ', '
    if hours:
        s += '%dh%02dm%02ds' % (hours, mins, secs)
    elif mins:
        s += '%dm%02ds' % (mins, secs)
    else:
        s += '%ds' % secs
    if not short or not secs:
        s += ('%.3f' % (float(td.microseconds) / 1000000))[2:]
    return s


class Connection:
    """A SSH connection"""

    def __init__(self, nb, datagrams, start_time, duration,
                 client_ip, server_ip, client_port, server_port,
                 client_protocol, server_protocol,
                 client_algos, server_algos, is_ssh):
        self.nb = nb
        self.logger = logging.getLogger('Conn%d' % self.nb)
        self.datagrams = datagrams # list of Datagram instances
        self.start_time = start_time # instance of datetime.datetime
        self.duration = duration # instance of datetime.timedelta
        self.client_ip = client_ip # string e.g. '123.234.0.42'
        self.server_ip = server_ip # string e.g. '123.234.13.37'
        self.client_port = client_port # int
        self.server_port = server_port # int
        # client and server protocol: None or string
        # (e.g. 'SSH-2.0-OpenSSH_5 Trisquel-5.5')
        self.client_protocol = client_protocol
        self.server_protocol = server_protocol
        self.client_algos = client_algos # None or dict
        self.server_algos = server_algos # None or dict
        self.client_sent_nb_datagrams = sum(1 for p in self.datagrams
                                         if p.sent_by_client)
        self.server_sent_nb_datagrams = sum(1 for p in self.datagrams
                                         if not p.sent_by_client)
        self.client_sent_len = sum(p.total_len for p in self.datagrams
                                 if p.sent_by_client)
        self.server_sent_len = sum(p.total_len for p in self.datagrams
                                 if not p.sent_by_client)
        self.ssh = is_ssh

    def __repr__(self):
        return '<Connection %d>' % self.nb

    def __str__(self):
        return repr(self)

    def compute_rtt(self):
        """Set an approximate RTT for each datagram in self.datagrams"""
        # Step1: compute RTT for the very last packet being acked
        # (ignore multiple acks in one)
        self.datagrams.reverse()
        last_acking = {True: None, False: None}
        has_rtt = {True: False, False: False} # both ways have no RTTs
        for datagram in self.datagrams:
            if last_acking[not datagram.sent_by_client] is not None \
                    and datagram.seq_nb \
                        < last_acking[not datagram.sent_by_client].ack:
                # this last_acking is acking datagram
                datagram.rtt = (last_acking[not datagram.sent_by_client].time \
                                   - datagram.time) * 2
                has_rtt[datagram.sent_by_client] = True
                last_acking[not datagram.sent_by_client] = None
            if datagram.ack > -1:
                last_acking[datagram.sent_by_client] = datagram
        self.datagrams.reverse()
        # Step1 (bis): if no RTTs in both ways, returns
        if not has_rtt[True] and not has_rtt[False]:
            self.logger.warning('Failed to compute RTTs')
            return
        # Step1 (ter): if no RTTs in one way, take RTTs from the other way
        if has_rtt[True] != has_rtt[False]: # xor
            way = has_rtt[True] # RTTs in datagrams sent by client?
            last_rtt = None
            for datagram in self.datagrams:
                if datagram.sent_by_client == way:
                    last_rtt = datagram.rtt
                elif last_rtt is not None:
                    datagram.rtt = last_rtt
                    last_rtt = None
        # Step2: estimate the other RTTs
        last_rtt = {True: None, False: None}
        empty_rtts = {True: [], False: []}
        for datagram in self.datagrams:
            if datagram.rtt is None:
                # add this datagram to the list to be RTTed
                empty_rtts[datagram.sent_by_client].append(datagram)
            else:
                if empty_rtts[datagram.sent_by_client]:
                    if last_rtt[datagram.sent_by_client] is None:
                        # if it is the first RTTed packet in this way
                        # just recopy the RTT to the previous ones
                        for d in empty_rtts[datagram.sent_by_client]:
                            d.rtt = datagram.rtt
                    else:
                        # if it is not the first RTTed packet in this way
                        # do a linear interpolation of the RTT
                        diff = datagram.rtt \
                                         - last_rtt[datagram.sent_by_client]
                        diff /= 1 + len(empty_rtts[datagram.sent_by_client])
                        i = 1
                        for d in empty_rtts[datagram.sent_by_client]:
                            d.rtt = last_rtt[datagram.sent_by_client] \
                                        + i * diff
                            i += 1
                    # empty the list to be RTTed
                    empty_rtts[datagram.sent_by_client] = []
                # this packet has been RTTed in the previous step
                last_rtt[datagram.sent_by_client] = datagram.rtt
        # Step2 (cont.): maybe the last datagrams have not been RTTed
        for way in (True, False):
            if last_rtt[way] is None:
                # no packet have been RTTed in this way
                continue
            for d in empty_rtts[way]:
                # just recopy the RTT to the previous ones
                d.rtt = last_rtt[way]


class Datagram:
    """A datagram of a ssh connection"""

    def __init__(self, sent_by_client, time, seq_nb, total_len, payload_len, \
                                                                        ack):
        self.sent_by_client = sent_by_client # True or False
        self.time = time # instance of datetime.datetime
        self.seq_nb = seq_nb #int
        self.total_len = total_len # int length of the datagram
        self.payload_len = payload_len # int length of the payload
        self.ack = ack # int: -1 if not ACKed else seq_nb of the datagram ACKed
        self.rtt = None # instance of datetime.timedelta

    def __repr__(self):
        s = (
                'Datagram sent by %s\n'
                'Time: %s\n'
                'Sequence number: %d\n'
                'Payload length: %d bytes'
            ) % (
                C.FBlu + 'client' + C.FRes if self.sent_by_client
                else C.FYel + 'server' + C.FRes,
               self.time.strftime('%b %d, %Y - %H:%M:%S.%f'),
               self.seq_nb,
               self.payload_len
            )
        if self.ack > 0:
            s += '\nSequence number of datagram ACKed: %d' % self.ack
        if self.rtt is not None:
            s += '\nEstimate RTT: %s' % str_td(self.rtt)
        return s


    def __str__(self):
        return repr(self)


class ConnectionsRepr:
    """Representation of connection, one after the other"""

    def __init__(self, logger, full, plugins):
        self.logger = logger
        self.plugins = []
        self.plugins_fields = {}
        self.plugins_fields_table = {}
        if plugins:
            for plugin in plugins:
                try:
                    fields = plugin.plugin_object.result_fields()
                    fields_table = plugin.plugin_object.result_fields_table()
                except Exception as e:
                    if e.message:
                        self.logger.error('Plugin %s fatal error: %s, %s' %
                                (plugin.name, e.__class__.__name__, e.message))
                    else:
                        self.logger.error('Plugin %s fatal error: %s' %
                                (plugin.name, e.__class__.__name__))
                else:
                    self.plugins.append(plugin)
                    self.plugins_fields[plugin] = fields
                    self.plugins_fields_table[plugin] = fields_table
        self.full = full

    def repr(self, connection):
        """Representation of a connection"""
        raise NotImplementedError()

    def result_plugin(self, connection, plugin):
        """Apply and represent a plugin on a connection"""
        s = {}
        plugin_object = plugin.plugin_object
        self.logger.info('Analyse connection %d with plugin %s' \
                % (connection.nb, plugin.name))
        try:
            self.logger.debug('Activate the plugin')
            plugin_object.activate()
            self.logger.debug('Launch the analyse of the connection'
                    ' by the plugin')
            plugin_object.analyse(connection)
            self.logger.debug('Get the result of the analyse by the plugin')
            s = plugin_object.result_repr()
            self.logger.debug('Deactivate the plugin')
            plugin_object.deactivate()
        except RuntimeWarning as e:
            self.logger.warning('Plugin %s: %s' % (plugin.name, e.message))
        except Exception as e:
            if e.message:
                self.logger.error('Plugin %s crash: %s, %s' %
                        (plugin.name, e.__class__.__name__, e.message))
            else:
                self.logger.error('Plugin %s crash: %s' %
                        (plugin.name, e.__class__.__name__))
        return s

class ConnectionsNormalRepr(ConnectionsRepr):
    """Normal representation of connections"""

    def repr(self, connection):
        """Representation of a connection"""
        if self.full:
            self.repr_full(connection)
        else:
            self.repr_summary(connection)

    def repr_full(self, connection):
        """Full representation of a connection"""
        r = (
             'Connection %d: ' + C.FBlu + '%s' + C.FRes + ':' + C.FCya + '%d'
             + C.FRes + ' --> ' + C.FYel + '%s' + C.FRes + ':' + C.FGre
             + '%d' + C.FRes + '\n%s'
             'Start date: %s\n'
             'Duration: %s\n'
             'Datagrams sent by client: ' + C.FBlu + '%d ' + C.FRes + '(' +
                C.FBlu + '%d ' + C.FRes + 'bytes)\n'
             'Datagrams sent by server: ' + C.FYel + '%d ' + C.FRes + '(' +
                C.FYel + '%d ' + C.FRes + 'bytes)'
            ) % (
                connection.nb, connection.client_ip, connection.client_port,
                connection.server_ip, connection.server_port,
                '' if connection.ssh else C.FMag +
                    'Not detected as a ssh connection' + C.FRes + '\n',
                connection.start_time.strftime('%b %d, %Y - %H:%M:%S'),
                str_td(connection.duration),
                connection.client_sent_nb_datagrams, connection.client_sent_len,
                connection.server_sent_nb_datagrams, connection.server_sent_len
            )
        for plugin in self.plugins:
            plugin_results = self.result_plugin(connection, plugin)
            for field in self.plugins_fields[plugin]:
                if field in plugin_results:
                    r += '\n%s: %s' % (field, plugin_results[field])
        print '\n%s' % r.replace('\n', '\n  ')

    def repr_summary(self, connection):
        """A one-line summary of the connection"""
        print (
             '%s Connection %-3d: ' + C.FBlu + '%16s' + C.FRes + ':' + C.FCya +
             '%-5.d' + C.FRes + ' --> ' + C.FYel + '%16s' + C.FRes + ':' +
             C.FGre + '%-5d' + C.FRes + ' %s'
            ) % (
                ' ' if connection.ssh else C.FMag + '?' + C.FRes,
                connection.nb, connection.client_ip, connection.client_port,
                connection.server_ip, connection.server_port,
                connection.start_time.strftime('%m%b%y %H:%M:%S'),
            )

class ConnectionsTableRepr(ConnectionsNormalRepr):
    """Table representation of connections"""

    def repr_full(self, connection):
        """Full representation of a connection"""
        t = Texttable(78)
        t.set_deco(Texttable.HEADER | Texttable.VLINES)
        t.set_chars(['.', '|', 'o', '-'])
        t.header(['Field', 'Client', 'Server'])
        t.set_cols_align(['r', 'l', 'l'])
        t.add_row(['IP', connection.client_ip, connection.server_ip])
        t.add_row(['Port', connection.client_port, connection.server_port])
        t.add_row(['Datagrams', connection.client_sent_nb_datagrams,
            connection.server_sent_nb_datagrams])
        t.add_row(['Datagrams (bytes)', connection.client_sent_len,
            connection.server_sent_len])
        r = (
             'Connection %d\n%s'
             'Start date: %s\n'
             'Duration: %s'
            ) % (
                connection.nb, '' if connection.ssh else C.FMag +
                    'Not detected as a ssh connection' + C.FRes + '\n',
                connection.start_time.strftime('%b %d, %Y - %H:%M:%S'),
                str_td(connection.duration)
            )
        for plugin in self.plugins:
            plugin_results = self.result_plugin(connection, plugin)
            for field_short, field_client, field_server \
                    in self.plugins_fields_table[plugin]:
                if field_client not in plugin_results \
                        or plugin_results[field_client] is None:
                    plugin_results[field_client] = ''
                if field_server not in plugin_results \
                        or plugin_results[field_server] is None:
                    plugin_results[field_server] = ''
                if plugin_results[field_client] != '' \
                        or plugin_results[field_server] != '':
                    t.add_row([
                        field_short,
                        C.remove_color(plugin_results[field_client]),
                        C.remove_color(plugin_results[field_server])
                        ])
                del(plugin_results[field_client])
                del(plugin_results[field_server])
            for field in self.plugins_fields[plugin]:
                if field in plugin_results:
                    r += '\n%s: %s' % (field, plugin_results[field])
        r += '\n%s' % t.draw()
        print '%s\n' % r.replace('\n', '\n  ')

# Failback to ConnectionsNormalRepr if Texttable was not imported properly
if Texttable is None:
    ConnectionsTableRepr = ConnectionsNormalRepr

class ConnectionsCSVRepr(ConnectionsRepr):
    """Representation of a connection as CSV"""

    def __init__(self, logger, full, plugins, csv_writer):
        ConnectionsRepr.__init__(self, logger, full, plugins)
        self.csv_writer = csv_writer
        columns = ['Connection nb', 'Detected as SSH', 'Source IP',
            'Source port','Destination IP', 'Destinantion port', 'Start date']
        if self.full:
            columns.extend(['Duration',
                'Datargrams send by client',
                'Datagrams send by client in bytes',
                'Datargrams send by server',
                'Datagrams send by server in bytes'])
            for plugin in self.plugins:
                columns.extend(self.plugins_fields[plugin])
        self.csv_writer.writerow(columns)

    def repr(self, connection):
        """Representation of a connection"""
        columns = [
                connection.nb, # Connection nb
                1 if connection.ssh else 0, # Detected as SSH
                connection.client_ip, # Source IP'
                connection.client_port, # Source port
                connection.server_ip, # Destination IP
                connection.server_port, # Destinantion port
                connection.start_time.strftime('%d/%m/%Y %H:%M:%S') # Start date
                ]
        if self.full:
            columns.extend([
                connection.duration.total_seconds(), # Duration
                connection.client_sent_nb_datagrams, # Datargrams send by client
                connection.client_sent_len, # Datagrams send by client in bytes
                connection.server_sent_nb_datagrams, # Datargrams send by server
                connection.server_sent_len # Datagrams send by server in byte
                ])
            for plugin in self.plugins:
                plugin_results = self.result_plugin(connection, plugin)
                for field in self.plugins_fields[plugin]:
                    if field in plugin_results:
                        columns.append(plugin_results[field])
                    else:
                        columns.append('')
        self.csv_writer.writerow(columns)

class TestConnection(unittest.TestCase):
    """Unit tests for Connection"""

    def create_connection(self, oneway=False):
        """
        Create a connection

        10000 packets
        RTT between 0.1 and 0.9sec
        """
        now = datetime.now()
        time = now
        datagrams = []
        seq_nb = {True: random.randint(0, 10000),
                 False: random.randint(0, 10000)}
        for _ in xrange(10000):
            time += timedelta(microseconds=random.randint(100000, 449999))
            sent_by_client = random.choice((True, False))
            payload_len = random.randint(10, 100)
            total_len = payload_len + 40
            datagrams.append(Datagram(
                sent_by_client,
                time,
                seq_nb[sent_by_client],
                payload_len,
                total_len,
                -1 if sent_by_client and oneway else seq_nb[not sent_by_client]
                ))
            seq_nb[sent_by_client] += total_len
        connection = Connection(0, datagrams, now, time - now,
                '1.2.3.4', '5.6.7.8', 12345, 22, None, None, {}, {}, True)
        return connection

    def test_compute_rtt(self):
        """General test for computeRTT"""
        connection = self.create_connection()
        connection.compute_rtt()
        for datagram in connection.datagrams:
            self.assertGreaterEqual(datagram.rtt.total_seconds(), 0.1)
            self.assertLessEqual(datagram.rtt.total_seconds(), 0.9)

    def test_compute_rtt_oneway(self):
        """Test computeRTT in case of no ack in one way"""
        connection = self.create_connection(True)
        connection.compute_rtt()
        for datagram in connection.datagrams:
            self.assertGreaterEqual(datagram.rtt.total_seconds(), 0.1)
            self.assertLessEqual(datagram.rtt.total_seconds(), 0.9)


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
