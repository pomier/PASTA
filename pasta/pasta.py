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
    import logging, argparse

    # TODO: check the right version of Python

    # Arguments parsing
    parser = argparse.ArgumentParser(
        description = 'PASTA is another SSH traffic analyser',
        epilog = '' ) #FIXME: epilog
    parser.add_argument('-v', '--verbose', dest='verbose',
                        action='append_const', const=None,
                        help='print logging messages; multiple -v options '
                             'increase verbosity, maximum is 4')
    parser.add_argument('--logfile', metavar='file', dest='logfile',
                        default=None,
                        help='store logs in a file instead of standard output')
    args = parser.parse_args()

    # Logging
    if args.verbose:
        logger = logging.getLogger()
        logger.setLevel({
            1: logging.ERROR,
            2: logging.WARNING,
            3: logging.INFO,
            4: logging.DEBUG
            }[len(args.verbose)])
        formatter = logging.Formatter('%(asctime)s    %(levelname)7s    '
                                      '%(name)s    %(message)s')
        if args.logfile is None:
            handler = logging.StreamHandler()
        else:
            handler = logging.FileHandler(logfile)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:
        logging.raiseExceptions = False

    # TODO: to be continued

    # FIXME: temp, for test purposes
    l=logging.getLogger('Logger name')
    l.info('message 0')
    l.debug('message 1')
    l.warning('message 2')
    l.error('message 3')
