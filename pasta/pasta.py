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
Parse the arguments and launch PASTA according to them
"""


if __name__ == '__main__':
    import sys, argparse, logging, os
    import colors as C
    from pcap_parser import PcapParser

    # Check the right version of Python
    if sys.version_info[:2] != (2, 7):
        sys.stderr.write('PASTA must be run with Python 2.7\n')
        sys.exit(1)

    # Load the plugins on demand
    def load_plugins(parser, logger=None):
        # import yapsy if needed
        try:
            from yapsy.PluginManager import PluginManager
            from plugins import SingleConnectionAnalyser, \
                    InterConnectionsAnalyser
        except ImportError:
            parser.exit(status=3, message='PASTA plugins require yapsy.\n'
                'You may try [sudo] easy_install-2.7 yapsy\n'
                'Or use the option --no-plugins to disable the plugins\n')
        # create the plugin manager
        plugin_manager = PluginManager(
                categories_filter={
                        'SingleConnectionAnalyser': SingleConnectionAnalyser,
                        'InterConnectionsAnalyser': InterConnectionsAnalyser
                    },
                directories_list = [os.path.join(os.path.dirname(sys.argv[0]),
                        'plugins')],
                plugin_info_ext='plugin')
        plugin_manager.locatePlugins()
        def load_plugin(plugin):
            if logger is not None:
                logger.info('...plugin %s v.%s'
                        % (plugin.name, plugin.version))
        plugin_manager.loadPlugins(load_plugin)
        return plugin_manager

    # Define an argparse type for range of numbers
    def argparse_numbers(txt):
        """Is txt a valid range of numbers?"""
        numbers = set()
        for parts in txt.split(','):
            edges = parts.split('-')
            try:
                if len(edges) == 1:
                    numbers.add(int(edges[0]))
                elif len(edges) == 2:
                    numbers.update(range(int(edges[0]), int(edges[1]) + 1))
                else:
                    raise ValueError()
            except ValueError:
                raise argparse.ArgumentTypeError('not a valid argument')
        return numbers

    # Usage
    class PastaFormatter(argparse.RawDescriptionHelpFormatter):
        def _format_usage(self, usage, actions, groups, prefix):
            if prefix is None:
                prefix = 'usage: '
            # remove --list-plugins and -h
            new_actions = []
            for action in actions:
                for suppress in ('--list-plugins', '-h'):
                    if suppress in action.option_strings:
                        break
                else:
                    new_actions.append(action)
            # auto-generate usage
            usage = argparse.RawDescriptionHelpFormatter._format_usage\
                    (self, usage, new_actions, groups, prefix)
            usage = usage.rstrip()
            # add --list-plugins and -h
            usage += '\n%s%s --list-plugins' % (' ' * len(prefix), self._prog)
            usage += '\n%s%s --help' % (' ' * len(prefix), self._prog)
            usage += '\n\n'
            return usage

    # Arguments parsing
    parser = argparse.ArgumentParser(
        formatter_class=PastaFormatter, description= \
        '                     ____   _    ____ _____  _\n'
        '                    |  _ \ / \  / ___|_   _|/ \\\n'
        '                    | |_) / _ \ \___ \ | | / _ \\\n'
        '                    |  __/ ___ \ ___) || |/ ___ \\\n'
        '                    |_| /_/   \_\____/ |_/_/   \_\\\n'
        '                 PASTA is another SSH traffic analyser', epilog= \
        'Examples:\n'
        '  Get an overview of the SSH traffic:\n'
        '    %(prog)s -r file.pcap\n'
        '  Select some connections and get more precise informations:\n'
        '    %(prog)s -r file.pcap -n 2,4-6\n'
        '  See if there is other interesting connections:\n'
        '    %(prog)s -r file.pcap -a\n'
        '  Use some plugin to see links between ssh and non-ssh connections:\n'
        '    %(prog)s -r file.pcap -aS', add_help=False)
    parser_list_plugins = argparse.ArgumentParser(add_help=False)

    main_options = parser.add_argument_group('Main options')
    main_options.add_argument('-r', metavar='file.pcap', dest='inputFile',
                        required=True, help='filename to read from')
    main_options.add_argument('-n', metavar='nb', dest='connection_nb',
                              type=argparse_numbers, help='procede only these '
                              'connections (e.g.: 2,4-6 shows only the second,'
                              ' fourth, fifth and sixth connections);'
                              ' implies -S')
    main_options.add_argument('-a', '--all', dest='ssh_only',
                              action='store_false', help='keep connections '
                              'which do not look like ssh (slower)')
    main_options.add_argument('--tshark', metavar='cmd', dest='tshark_cmd',
                                 default='tshark', help='specify the tshark'
                                 ' binary to call')

    display_options = parser.add_argument_group('Display options')
    display_options.add_argument('--no-colors', dest='colors',
                                 action='store_false',
                                 help='disable colors in the output')

    group_summary = display_options.add_mutually_exclusive_group()
    group_summary.add_argument('-s', '--summary', action='store_true',
                               dest='summary', help='show only a summary of'
                               ' the ssh connections (faster)')
    group_summary.add_argument('-S', '--no-summary', action='store_false',
                               dest='no_summary', help='show all the'
                               ' informations of the ssh connections (slower)')

    plugins_options = parser.add_argument_group('Plugins options')
    parser_list_plugins.add_argument('--list-plugins', action='store_true',
                               dest='list_plugins', help='list the plugins')
    plugins_options.add_argument('--list-plugins', action='store_true',
                               dest='list_plugins', help='list the plugins')
    plugins_options.add_argument('--no-plugins', action='store_false',
                               dest='plugins', help='disactivate all plugins')

    logging_options = parser.add_argument_group('Logging options')
    logging_options.add_argument('-v', '--verbose', dest='verbose',
                                 action='count', help='print logging messages;'
                                 ' multiple -v options increase verbosity,'
                                 ' maximum is 4')
    logging_options.add_argument('--logfile', metavar='file', dest='logFile',
                                 default=None, help='store logs in a file'
                                 ' instead of standard output')
    help_options = parser.add_argument_group('Help')
    help_options.add_argument('-h', '--help', action='help',
                              help='show this help message and exit')

    if len(sys.argv) == 1:
        # program called without any arguments: show help and exit
        parser.exit(message=parser.format_help())

    # parse arguments
    # first, only --list-plugins (avoid -r to be required)
    args, remaining = parser_list_plugins.parse_known_args()
    if args.list_plugins:
        # disable loggin
        logging.disable(logging.ERROR)
        # we just want to print the list of plugins
        plugin_manager = load_plugins(parser)
        for category in plugin_manager.getCategories():
            print ''
            plugins = plugin_manager.getPluginsOfCategory(category)
            if len(plugins) == 0:
                print 'No plugin detected in category %s.' % category
            if len(plugins) == 1:
                print 'One plugin detected in category %s:' % category
            else:
                print '%s plugins detected in category %s:' \
                    % (len(plugins), category)
            for plugin in plugins:
                print '\n  %s v.%s' % (plugin.name, plugin.version)
                print '    %s' % '\n    '.join(plugin.description.split('\n'))
            print ''
        sys.exit(0)
    # then, the remaining
    args = parser.parse_args(remaining)

    # Security notice:
    # The validity of the files used as input/output is not tested at this
    # point, since it may create a security hole (race condition) due to the
    # time elapsed between this check and the real use of the file.
    # As a consequence, the real tests are done when the files are really used.


    # Logging
    if args.verbose:
        if args.verbose > 4:
            parser.error('--verbose: maximum of verbosity is 4')
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
                parser.error('--logfile: %s' % str(e.strerror).lower())
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:
        # disable loggin
        logging.disable(logging.ERROR)

    logger = logging.getLogger('PASTA')
    logger.info('Loggin set')

    if args.connection_nb is not None:
        logger.info('Connections to be considered: %s' \
                    % ', '.join('%d' % n for n in args.connection_nb))
    else:
        logger.info('Connections to be considered: all')


    # Computation of the datagrams
    compute_datagrams = args.connection_nb is not None
    compute_datagrams &= not args.summary
    compute_datagrams |= not args.no_summary
    logger.info('Datagrams are %sto be computed' \
                % ('' if compute_datagrams else 'not '))


    # Colors
    if args.colors:
        logger.info('Trying to enable colors')
        C.coloramaze()
    else:
        logger.info('Colors disabled')


    # Loading plugins
    if args.plugins or args.list_plugins:
        logger.info('Loading plugins...')
        plugin_manager = load_plugins(parser, logger)
    else:
        logger.info('Plugins disabled')

    # Pcap parser
    logger.info('Pcap parsing...')
    pcap_parser = PcapParser(keep_datagrams=compute_datagrams,
            tshark_cmd=args.tshark_cmd)
    # if args.connection_nb is an empty set, ask for all connections
    connection_nb = args.connection_nb if args.connection_nb else None
    connections = pcap_parser.parse(args.inputFile, connection_nb,
            args.ssh_only)


    # RTT
    if compute_datagrams:
        logger.info('RTT computations...')
        for connection in connections:
            connection.compute_RTT()


    # Printing connections
    logger.info('Printing connections...')
    for connection in connections:
        if not compute_datagrams:
            print connection.summary()
            break
        print connection
        # SingleConnectionAnalyser plugins
        if args.plugins:
            logger.info('Analyse connection %d (plugins)', connection.nb)
            for plugin in plugin_manager.getPluginsOfCategory\
                    ("SingleConnectionAnalyser"):
                plugin_object = plugin.plugin_object
                logger.info('Using plugin %s' % plugin.name)
                try:
                    logger.debug('Activate the plugin')
                    plugin_object.activate()
                    logger.debug('Launch the analyse of the connection'
                            ' by the plugin')
                    plugin_object.analyse(connection)
                    logger.debug('Print the result of the analyse'
                            ' by the plugin')
                    print plugin_object.result_repr()
                    logger.debug('Deactivate the plugin')
                    plugin_object.deactivate()
                except RuntimeWarning as e:
                    logger.warning('Plugin %s: %s' % (plugin.name, e.message))
                except Exception as e:
                    if e.message:
                        logger.error('Plugin %s crash: %s, %s' %
                                (plugin.name, e.__class__.__name__, e.message))
                    else:
                        logger.error('Plugin %s crash: %s' %
                                (plugin.name, e.__class__.__name__))
        print

    # InterConnectionsAnalyser plugins
    if args.plugins and compute_datagrams:
        print
        logger.info('Analyse inter-connections (plugins)')
        for plugin in plugin_manager.getPluginsOfCategory\
                ("InterConnectionsAnalyser"):
            plugin_object = plugin.plugin_object
            logger.info('Using plugin %s' % plugin.name)
            try:
                logger.debug('Activate the plugin')
                plugin_object.activate()
                logger.debug('Launch the analyse of the connections'
                        ' by the plugin')
                plugin_object.analyse(connections)
                logger.debug('Print the result of the analyse by the plugin')
                print plugin_object.result_repr() + '\n'
                logger.debug('Deactivate the plugin')
                plugin_object.deactivate()
            except RuntimeWarning as e:
                logger.warning('Plugin %s: %s' % (plugin.name, e.message))
            except Exception as e:
                if e.message:
                    logger.error('Plugin %s crash: %s, %s' %
                            (plugin.name, e.__class__.__name__, e.message))
                else:
                    logger.error('Plugin %s crash: %s' %
                            (plugin.name, e.__class__.__name__))
