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
                 clientProtocol, serverProtocol):
        self.nb = nb
        self.logger = logging.getLogger('Conn%d' % self.nb)
        self.datagrams = datagrams # list of Datagram instances
        self.startTime = startTime # instance of datetime.datetime
        self.duration = duration # instance of datetime.timedelta
        self.clientIP = clientIP # string e.g. '123.234.0.42'
        self.serverIP = serverIP # string e.g. '123.234.13.37'
        self.clientPort = clientPort # int
        self.serverPort = serverPort # int
        self.clientProtocol = clientProtocol # None or string eg. "OpenSSH 5.3"
        self.serverProtocol = serverProtocol # None or string eg. "OpenSSH 5.2"
        self.clientSentNbDatagrams = sum(1 for p in self.datagrams
                                         if p.sentByClient)
        self.serverSentNbDatagrams = sum(1 for p in self.datagrams
                                         if not p.sentByClient)
        self.clientSentLen = sum(p.totalLen for p in self.datagrams
                                 if p.sentByClient)
        self.serverSentLen = sum(p.totalLen for p in self.datagrams
                                 if not p.sentByClient)
        self.idleTime = None # [Task3] e.g. 0.31415 (for 31.14%)
        self.connectionType = None # [Task3] e.g. 'shell', 'ssh', 'tunnel'
        #                           [Task4] other things
        # TODO: other things for Task4

    def __repr__(self):
        s = (
             'Connection %d: ' + C.FBlu + '%s' + C.FRes + ':' + C.FCya + '%d'
             + C.FRes + ' --> ' + C.FYel + '%s' + C.FRes + ':' + C.FGre
             + '%d' + C.FRes + '\n'
             'Start date: %s\n'
             'Duration: %s\n'
             'Client: %s\n'
             'Server: %s\n'
             'Datagrams sent by client: ' + C.FBlu + '%d ' + C.FRes + '(' +
                C.FBlu + '%d ' + C.FRes + 'bytes)\n'
             'Datagrams sent by server: ' + C.FYel + '%d ' + C.FRes + '(' +
                C.FYel + '%d ' + C.FRes + 'bytes)'
            ) % (
                self.nb, self.clientIP, self.clientPort,
                self.serverIP, self.serverPort,
                self.startTime.strftime('%b %d, %Y - %H:%M:%S'),
                strTD(self.duration),
                'unknown'
                    if self.clientProtocol is None
                    else (C.FBlu + '%s' + C.FRes) % self.clientProtocol,
                'unknown'
                    if self.serverProtocol is None
                    else (C.FYel + '%s' + C.FRes) % self.serverProtocol,
                self.clientSentNbDatagrams, self.clientSentLen,
                self.serverSentNbDatagrams, self.serverSentLen
            )
        if self.idleTime is not None:
            s += '\nIdle time: %.1f%%' % (self.idleTime * 100)
        if self.connectionType is not None:
            s += '\nConnexion type: %s' % self.connectionType
        return s

    def __str__(self):
        return repr(self)

    def summary(self):
        """A one-line summary of the connection"""
        # FIXME: We don't have the duration in summary mode (show startTime ?)
        s = (
             'Connection %d: ' + C.FBlu + '%s' + C.FRes + ':' + C.FCya +
             '%-5.d' + C.FRes + ' --> ' + C.FYel + '%s' + C.FRes + ':' + C.FGre
             + '%-5d' + C.FRes + ' %s'
            ) % (
                self.nb, self.clientIP, self.clientPort,
                self.serverIP, self.serverPort,
                strTD(self.duration, short=True)
            )
        if self.idleTime is not None:
            s += ', %.1f%% idle' % (self.idleTime * 100)
        if self.connectionType is not None:
            s += ', %s' % self.connectionType
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
                        diff= datagram.RTT \
                                         - last_RTT[datagram.sentByClient]
                        diff/= 1 + len(empty_RTTs[datagram.sentByClient])
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



if __name__ == '__main__':

    import unittest, random, sys
    from datetime import datetime, timedelta

    if sys.version_info[:2] != (2, 7):
        sys.stderr.write('PASTA must be run with Python 2.7\n')
        sys.exit(1)

    class TestConnection(unittest.TestCase):
        random.seed(42)

        def create_connection(self, oneway=False):
            """Create a connection"""
            now = datetime.now()
            time = now
            datagrams = []
            seqNb = {True: random.randint(0, 10000),
                     False: random.randint(0, 10000)}
            for i in range(10000):
                time += timedelta(0, 0, random.randint(100000, 449999))
                sentByClient = random.choice((True, False))
                totalLen = random.randint(10, 100)
                datagrams.append(Datagram(
                    sentByClient,
                    time,
                    seqNb[sentByClient],
                    totalLen,
                    totalLen + 40,
                    -1 if sentByClient and oneway else seqNb[not sentByClient]
                    ))
                seqNb[sentByClient] += totalLen
            connection = Connection(0, datagrams, now, time - now,
                    '1.2.3.4', '5.6.7.8', 12345, 22, 'Foo', 'Bar')
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

    unittest.main()
