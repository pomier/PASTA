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



if __name__ == '__main__':
    import logging, argparse, sys
    from pcap_parser import PcapParser
    from colors import Coloramaze

    # TODO: check the right version of Python

    # Arguments parsing
    parser = argparse.ArgumentParser(
        description = 'PASTA is another SSH traffic analyser',
        epilog = '' ) #FIXME: epilog
    parser.add_argument('-r', metavar='file.pcap', dest='inputFile',
                        required=True, help='filename to read from')
    parser.add_argument('-s', '--summary', action='store_true',
                        help='show only a summary of the ssh connections')
    parser.add_argument('-v', '--verbose', dest='verbose', action='count',
                        help='print logging messages; multiple -v options '
                             'increase verbosity, maximum is 4')
    parser.add_argument('--logfile', metavar='file', dest='logFile',
                        default=None,
                        help='store logs in a file instead of standard output')
    args = parser.parse_args()

    # Security notice:
    # The validity of the files used as input/output is not tested at this
    # point, since it may create a security hole (race condition) due to the
    # time elapsed between this check and the real use of the file.
    # As a consequence, the real tests are done when the files are really used.

    # Logging
    if args.verbose:
        logger = logging.getLogger()
        logger.setLevel({
            1: logging.ERROR,
            2: logging.WARNING,
            3: logging.INFO,
            4: logging.DEBUG
            }[args.verbose])
        formatter = logging.Formatter('%(asctime)s    %(levelname)7s    '
                                      '%(name)10s    %(message)s')
        if args.logFile is None:
            handler = logging.StreamHandler()
        else:
            try:
                handler = logging.FileHandler(args.logFile)
            except IOError as e:
                print 'Error while opening file %s for logging: %s' % (
                      e.filename, e.strerror)
                sys.exit(1)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:
        logging.raiseExceptions = False

    logger = logging.getLogger('PASTA')
    logger.info('Loggin set')
    
    # Colors
    # TODO: check if we want to have colors or not
    Coloramaze()
    logger.info('Colors set')

    # Pcap parser
    pcapParser = PcapParser(keep_datagrams=not args.summary)
    logger.info('PcapParser set')
    connections = pcapParser.parse(args.inputFile)

    # Printing connections
    logger.info('Printing connections')
    for connection in connections:
        if args.summary:
            print connection.summary()
        else:
            print '\n%s\n' % connection
