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

Stand alone program:
    tshark (mandatory)
    python v.2.7

Python 2.7 libraries:
    argparse (mandatory)
    yapsy (kind of mandatory)
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
    - the idle time (a percentage representing how busy the connection was).
    - the connection type (tunnel, scp (up/down), shell, or reverse shell).

Pasta can also detect stepping stones, depending on the point of 
view (client-side, proxy-side, server-side).


WARNING

If the beginning of a connection is missing, the program will not be able to
determine if the connection is a ssh one.

About the plugin stepping_stone_detection_serverside :
The algorithm used requires the client to send small packets at regular intervals 
to the server, according to the paper Stepping Stone Detection at The Server Side 
by Ruei-Min Lin, Yi-Chun Chou, and Kuan-Ta Chen. Considering too that the 
intervals of generated packets at the client are not known by the program, the 
plugin will not work if Nagle's algorithm is disabled at the client.


--
TODO: rest of the file (description of the software, requirements, how
      to use, install, explain that some connections can't be detected, etc)
      - may be done later
