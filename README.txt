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

# FIXME : allowed to give links for downloads ? 
# FIXME : To put in INSTALLATION section ?

Stand alone program:
    tshark (mandatory) - Included in Wireshark packaged
		       - Download page : http://www.wireshark.org/download.html
    python v.2.7 - Download page : http://www.python.org/getit/releases/2.7/

Python 2.7 libraries:
    argparse (mandatory) - Download page : http://pypi.python.org/pypi/argparse
    colorama (optional) - Download page : http://pypi.python.org/pypi/colorama


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

# FIXME : complete DETAILED DESCRIPTION section (with Task4 too)


WARNING
# FIXME : to correct, depending of the future implementation (keeping 
#         uncompleted connections on port 22 ?)

If the beginning of a connection is missing, the program will not be able to
determine if the connection is a ssh one, and will be discarded.


--
TODO: rest of the file (description of the software, requirements, how
      to use, install, explain that some connections can't be detected, etc)
      - may be done later
