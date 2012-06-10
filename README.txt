                             ____   _    ____ _____  _
                            |  _ \ / \  / ___|_   _|/ \
                            | |_) / _ \ \___ \ | | / _ \
                            |  __/ ___ \ ___) || |/ ___ \
                            |_| /_/   \_\____/ |_/_/   \_\
                         PASTA is another SSH traffic analyser



AUTHORS

The PASTA team (also known as the Spaghetteam):
    César 'Mr. Blue' Burini
    Pierre 'Rogdham' Pavlidès
    Romain 'Haradwaith' Pomier


REQUIREMENTS

Stand alone programs:
    tshark (mandatory)
    python v.2.7

Python 2.7 libraries:
    argparse (mandatory)
    yapsy (recommanded)
    colorama (optional)


INSTALLATION

# TODO : complete INSTALLATION section


DESCRIPTION

PASTA is another ssh traffic analyser.
As such, it analyses ssh connection in a capture file. Based on the traffic
patterns, information such as idle time or connection type are estimated.
See the DETAILED DESCRIPTION to get more precise information.


KNOWN BUGS

A bug in some modified versions of argparse are making the -s and -S options
non-exclusive. In that case, if they are used together, it would be as if -s
was not used.


USAGE

Launch pasta.py without any arguments, or with the -h or --help flag to see the
usage and description of the options.


DETAILED DESCRIPTION

All the fields given by Pasta about the ssh connections are:
    - the client address.
    - the server address.
    - the start date.
    - the duration.
    - the protocol used by the client.
    - the protocol used by the server.
    - the number of datagrams sent by the client, and the number of bytes.
    - the number of datagrams sent by the server, and the number of bytes.

Also, different plugins can detect:
    - the type of connection (ssh, scp, etc)
    - the idle time
    - stepping stones
    - ...
Fore more information about the plugins, look at the .plugin files.


WARNING

If the beginning of a connection is missing, the program will not be able to
determine if the connection is a ssh one. Hence, use the -a option.


--
TODO: rest of the file (description of the software, requirements, how
      to use, install, explain that some connections can't be detected, etc)
