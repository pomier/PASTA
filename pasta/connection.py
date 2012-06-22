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



import logging, unittest, random
from datetime import datetime, timedelta
import colors as C

def strTD(td, short=False):
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

    def __init__(self, nb, datagrams, startTime, duration,
                 clientIP, serverIP, clientPort, serverPort,
                 clientProtocol, serverProtocol,
                 clientAlgos, serverAlgos, is_ssh):
        self.nb = nb
        self.logger = logging.getLogger('Conn%d' % self.nb)
        self.datagrams = datagrams # list of Datagram instances
        self.startTime = startTime # instance of datetime.datetime
        self.duration = duration # instance of datetime.timedelta
        self.clientIP = clientIP # string e.g. '123.234.0.42'
        self.serverIP = serverIP # string e.g. '123.234.13.37'
        self.clientPort = clientPort # int
        self.serverPort = serverPort # int
        # client and server protocol: None or string
        # (e.g. 'SSH-2.0-OpenSSH_5 Trisquel-5.5')
        self.clientProtocol = clientProtocol
        self.serverProtocol = serverProtocol
        self.clientAlgos = clientAlgos # None or dict
        self.serverAlgos = serverAlgos # None or dict
        self.clientSentNbDatagrams = sum(1 for p in self.datagrams
                                         if p.sentByClient)
        self.serverSentNbDatagrams = sum(1 for p in self.datagrams
                                         if not p.sentByClient)
        self.clientSentLen = sum(p.totalLen for p in self.datagrams
                                 if p.sentByClient)
        self.serverSentLen = sum(p.totalLen for p in self.datagrams
                                 if not p.sentByClient)
        self.ssh = is_ssh

    def __repr__(self):
        s = (
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
                self.nb, self.clientIP, self.clientPort,
                self.serverIP, self.serverPort,
                '' if self.ssh else C.FMag +
                    'Not detected as a ssh connection' + C.FRes + '\n',
                self.startTime.strftime('%b %d, %Y - %H:%M:%S'),
                strTD(self.duration),
                self.clientSentNbDatagrams, self.clientSentLen,
                self.serverSentNbDatagrams, self.serverSentLen
            )
        return s

    def __str__(self):
        return repr(self)

    def summary(self):
        """A one-line summary of the connection"""
        s = (
             '%s Connection %-3d: ' + C.FBlu + '%16s' + C.FRes + ':' + C.FCya +
             '%-5.d' + C.FRes + ' --> ' + C.FYel + '%16s' + C.FRes + ':' +
             C.FGre + '%-5d' + C.FRes + ' %s'
            ) % (
                ' ' if self.ssh else C.FMag + '?' + C.FRes,
                self.nb, self.clientIP, self.clientPort,
                self.serverIP, self.serverPort,
                self.startTime.strftime('%m%b%y %H:%M:%S'),
            )
        return s

    def compute_RTT(self):
        """Set an approximate RTT for each datagram in self.datagrams"""
        # Step1: compute RTT for the very last packet being acked
        # (ignore multiple acks in one)
        self.datagrams.reverse()
        last_acking = {True: None, False: None}
        has_RTT = {True: False, False: False} # both ways have no RTTs
        for datagram in self.datagrams:
            if last_acking[not datagram.sentByClient] is not None \
                    and datagram.seqNb \
                        < last_acking[not datagram.sentByClient].ack:
                # this last_acking is acking datagram
                datagram.RTT = (last_acking[not datagram.sentByClient].time \
                                   - datagram.time) * 2
                has_RTT[datagram.sentByClient] = True
                last_acking[not datagram.sentByClient] = None
            if datagram.ack > -1:
                last_acking[datagram.sentByClient] = datagram
        self.datagrams.reverse()
        # Step1 (bis): if no RTTs in both ways, returns
        if not has_RTT[True] and not has_RTT[False]:
            self.logger.warning('Failed to compute RTTs')
            return
        # Step1 (ter): if no RTTs in one way, take RTTs from the other way
        if has_RTT[True] != has_RTT[False]: # xor
            way = has_RTT[True] # RTTs in datagrams sent by client?
            last_RTT = None
            for datagram in self.datagrams:
                if datagram.sentByClient == way:
                    last_RTT = datagram.RTT
                elif last_RTT is not None:
                    datagram.RTT = last_RTT
                    last_RTT = None
        # Step2: estimate the other RTTs
        # FIXME: we may put an averaging system here (as in TCP)
        #        (i.e. no need for a third loop on datagrams)
        last_RTT = {True: None, False: None}
        empty_RTTs = {True: [], False: []}
        for datagram in self.datagrams:
            if datagram.RTT is None:
                # add this datagram to the list to be RTTed
                empty_RTTs[datagram.sentByClient].append(datagram)
            else:
                if empty_RTTs[datagram.sentByClient]:
                    if last_RTT[datagram.sentByClient] is None:
                        # if it is the first RTTed packet in this way
                        # just recopy the RTT to the previous ones
                        for d in empty_RTTs[datagram.sentByClient]:
                            d.RTT = datagram.RTT
                    else:
                        # if it is not the first RTTed packet in this way
                        # do a linear interpolation of the RTT
                        diff = datagram.RTT \
                                         - last_RTT[datagram.sentByClient]
                        diff /= 1 + len(empty_RTTs[datagram.sentByClient])
                        i = 1
                        for d in empty_RTTs[datagram.sentByClient]:
                            d.RTT = last_RTT[datagram.sentByClient] \
                                        + i * diff
                            i += 1
                    # empty the list to be RTTed
                    empty_RTTs[datagram.sentByClient] = []
                # this packet has been RTTed in the previous step
                last_RTT[datagram.sentByClient] = datagram.RTT
        # Step2 (cont.): maybe the last datagrams have not been RTTed
        for way in (True, False):
            if last_RTT[way] is None:
                # no packet have been RTTed in this way
                continue
            for d in empty_RTTs[way]:
                # just recopy the RTT to the previous ones
                d.RTT = last_RTT[way]

        #self.smooth_RTT()


    def smooth_RTT(self):
        """Smooth the RTTs"""
        # FIXME: fusion (way be done inside)
        from datetime import datetime, timedelta
        # ^^^ FIXME imports: put on top of the file + remove from the unit test

        alpha = 0.125
        last_rtt = {True: None, False: None}
        for datagram in self.datagrams:
            way = datagram.sentByClient
            if last_rtt[way] is None:
                last_rtt[way] = datagram.RTT.total_seconds()
            else:
                last_rtt[way] = (1 - alpha) * last_rtt[way] + \
                        alpha * datagram.RTT.total_seconds()
                datagram.RTT = timedelta(seconds = last_rtt[way])


class Datagram:
    """A datagram of a ssh connection"""

    def __init__(self, sentByClient, time, seqNb, totalLen, payloadLen, ack):
        self.sentByClient = sentByClient # True or False
        self.time = time # instance of datetime.datetime
        self.seqNb = seqNb #int
        self.totalLen = totalLen # int length of the datagram
        self.payloadLen = payloadLen # int length of the payload
        self.ack = ack # int: -1 if not ACKed else seqnb of the datagram ACKed
        self.RTT = None # instance of datetime.timedelta

    def __repr__(self):
        s = (
                'Datagram sent by %s\n'
                'Time: %s\n'
                'Sequence number: %d\n'
                'Payload length: %d bytes'
            ) % (
                C.FBlu + 'client' + C.FRes if self.sentByClient
                else C.FYel + 'server' + C.FRes,
               self.time.strftime('%b %d, %Y - %H:%M:%S.%f'),
               self.seqNb,
               self.payloadLen
            )
        if self.ack > 0:
            s += '\nSequence number of datagram ACKed: %d' % self.ack
        if self.RTT is not None:
            s += '\nEstimate RTT: %s' % strTD(self.RTT)
        return s


    def __str__(self):
        return repr(self)


class ConnectionsRepr:
    """Representation of connection, one after the other"""

    def __init__(self, logger, full, plugins):
        self.logger = logger
        self.plugins = []
        self.plugins_fields = {}
        for plugin in plugins:
            try:
                fields = plugin.plugin_object.fields_repr()
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
                C.FYel + '%d ' + C.FRes + 'bytes)\n'
            ) % (
                connection.nb, connection.clientIP, connection.clientPort,
                connection.serverIP, connection.serverPort,
                '' if connection.ssh else C.FMag +
                    'Not detected as a ssh connection' + C.FRes + '\n',
                connection.startTime.strftime('%b %d, %Y - %H:%M:%S'),
                strTD(connection.duration),
                connection.clientSentNbDatagrams, connection.clientSentLen,
                connection.serverSentNbDatagrams, connection.serverSentLen
            )
        for plugin in self.plugins:
            plugin_results = self.result_plugin(connection, plugin)
            for field in self.plugins_fields[plugin]:
                if field in plugin_results:
                    r += '%s: %s\n' % (field, plugin_results[field])
        print r

    def repr_summary(self, connection):
        """A one-line summary of the connection"""
        print (
             '%s Connection %-3d: ' + C.FBlu + '%16s' + C.FRes + ':' + C.FCya +
             '%-5.d' + C.FRes + ' --> ' + C.FYel + '%16s' + C.FRes + ':' +
             C.FGre + '%-5d' + C.FRes + ' %s'
            ) % (
                ' ' if connection.ssh else C.FMag + '?' + C.FRes,
                connection.nb, connection.clientIP, connection.clientPort,
                connection.serverIP, connection.serverPort,
                connection.startTime.strftime('%m%b%y %H:%M:%S'),
            )

class ConnectionsCSVRepr(ConnectionsRepr):
    """Representation of a connection as CSV"""

    def __init__(self, logger, full, plugins, csv_writer):
        ConnectionsRepr.__init__(self, logger, full, plugins)
        self.csv_writer = csv_writer
        columns = ['Connection nb', 'Detected as SSH', 'Source IP', 'Source port',
                'Destination IP', 'Destinantion port', 'Start date']
        if self.full:
            columns.extend(['Duration',
                'Datargrams send by client', 'Datagrams send by client in bytes',
                'Datargrams send by server', 'Datagrams send by server in bytes'])
            for plugin in self.plugins:
                columns.extend(self.plugins_fields[plugin])
        self.csv_writer.writerow(columns)

    def repr(self, connection):
        """Representation of a connection"""
        columns = [
                connection.nb, # Connection nb
                1 if connection.ssh else 0, # Detected as SSH
                connection.clientIP, # Source IP'
                connection.clientPort, # Source port
                connection.serverIP, # Destination IP
                connection.serverPort, # Destinantion port
                connection.startTime.strftime('%d/%m/%Y %H:%M:%S') # Start date
                ]
        if self.full:
            columns.extend([
                connection.duration.total_seconds(), # Duration
                connection.clientSentNbDatagrams, # Datargrams send by client
                connection.clientSentLen, # Datagrams send by client in bytes
                connection.serverSentNbDatagrams, # Datargrams send by server
                connection.serverSentLen # Datagrams send by server in byte
                ])
            for plugin in self.plugins:
                plugin_results = self.result_plugin(connection, plugin)
                for field in self.plugins_fields[plugin]:
                    if field in plugin_results:
                        column.append(plugin_results[field])
                    else:
                        column.append('')
                else:
                    columns.extend(plugin_result)
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
        seqNb = {True: random.randint(0, 10000),
                 False: random.randint(0, 10000)}
        for _ in xrange(10000):
            time += timedelta(microseconds=random.randint(100000, 449999))
            sentByClient = random.choice((True, False))
            payloadLen = random.randint(10, 100)
            totalLen = payloadLen + 40
            datagrams.append(Datagram(
                sentByClient,
                time,
                seqNb[sentByClient],
                payloadLen,
                totalLen,
                -1 if sentByClient and oneway else seqNb[not sentByClient]
                ))
            seqNb[sentByClient] += totalLen
        connection = Connection(0, datagrams, now, time - now,
                '1.2.3.4', '5.6.7.8', 12345, 22, None, None, {}, {}, True)
        return connection

    def test_compute_RTT(self):
        """General test for computeRTT"""
        connection = self.create_connection()
        connection.compute_RTT()
        for datagram in connection.datagrams:
            self.assertGreaterEqual(datagram.RTT.total_seconds(), 0.1)
            self.assertLessEqual(datagram.RTT.total_seconds(), 0.9)

    def test_compute_RTT_oneway(self):
        """Test computeRTT in case of no ack in one way"""
        connection = self.create_connection(True)
        connection.compute_RTT()
        for datagram in connection.datagrams:
            self.assertGreaterEqual(datagram.RTT.total_seconds(), 0.1)
            self.assertLessEqual(datagram.RTT.total_seconds(), 0.9)


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
