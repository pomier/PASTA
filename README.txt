                             ____   _    ____ _____  _
                            |  _ \ / \  / ___|_   _|/ \
                            | |_) / _ \ \___ \ | | / _ \
                            |  __/ ___ \ ___) || |/ ___ \
                            |_| /_/   \_\____/ |_/_/   \_\
                         PASTA is another SSH traffic analyser



AUTHORS

The PASTA team:
# FIXME : or "The Spaghet-team" ? :D
    César 'Mr. Blue' Burini
    Pierre 'Rogdham' Pavlidès
    Romain 'Haradwaith' Pomier


REQUIREMENTS

Stand alone program:
    tshark (mandatory)
    python v.2.7

Python 2.7 libraries:
    argparse (mandatory)
    colorama (optional)


INSTALLATION
# FIXME: to complete.


DESCRIPTION

PASTA allows you to analyze ssh connections detected in .pcap files. It can
show you several informations about theses ssh connections, such as for 
instance the addresses of the client and the server, the duration, or an 
estimation of the connection type (cf. DETAILED DESCRIPTION to learn more 
about all the possible fields). You can also choose specific ssh connections 
in the .pcap file, or add colors to the results.


KNOWN BUGS

A bug in some modified versions of argparse are making the -s and -S options
non-exclusive. In that case, if they are used together, it would be as if -s
is not used.


HOW TO USE
# FIXME : to complete.

Main options:
  -r file.pcap      filename to read from
  -n nb             procede only these connections (e.g.: 2,4-6 shows only the
                    second, fourth, fifth and sixth connections); implies -S

Display options:
  --no-colors       disable colors in the output
  -s, --summary     show only a summary of the ssh connections
  -S, --no-summary  show all the informations of the ssh connections

Logging options:
  -v, --verbose     print logging messages; multiple -v options increase
                    verbosity, maximum is 4
  --logfile file    store logs in a file instead of standard output

Help:
  -h, --help        show this help message and exit

Examples:
  Get an overview of the SSH traffic:
    pasta.py -r file.pcap
  Select some connections and get more precise informations:
    pasta.py -r file.pcap -n 2,4-6


DETAILED DESCRIPTION
# FIXME : to complete (with Task4 too)

All the fields given by Pasta about the ssh connections are:
    - the client address.
    - the server address.
    - the start date.
    - the duration.
    - the protocol used by the client.
    - the protocol used by the server.
    - the number of datagrams sent by the client, and the number of bytes.
    - the number of datagrams sent by the server, and the number of bytes.
    - the idle time (a percentage representing how busy was the connection).
    - the connexion type (tunnel, scp (up/down), shell, or reverse shell).


WARNING
# FIXME : to correct, depending of the future implementation (keeping 
uncompleted connections on port 22 ?)

If the beginning of a connection is missing, the program will not be able to
determine if the connection is a ssh one, and will be discarded.


--
TODO: rest of the file (description of the software, requirements, how
      to use, install, explain that some connections can't be detected, etc)
      - may be done later
