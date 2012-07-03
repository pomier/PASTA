                             ____   _    ____ _____  _
                            |  _ \ / \  / ___|_   _|/ \
                            | |_) / _ \ \___ \ | | / _ \
                            |  __/ ___ \ ___) || |/ ___ \
                            |_| /_/   \_\____/ |_/_/   \_\
                         PASTA is another SSH traffic analyser



AUTHORS

The PASTA team (or Spaghetteam):
    César 'Mr. Blue' Burini
    Pierre 'Rogdham' Pavlidès
    Romain 'Haradwaith' Pomier


REQUIREMENTS

Stand alone programs:
    python 2.7 (mandatory)
    tshark (mandatory)

Python 2.7 libraries:
    yapsy (recommanded)
    colorama (optional)
    texttable (optional)


REQUIREMENTS INSTALLATION

To install python2.7 and tshark, use the package manager of your system if any,
or go to
  - http://www.python.org/getit/releases/2.7/ for python2.7
  - http://www.wireshark.org/download.html for thsark

To install the python libraries, you may use pip:
    pip install -r requirements.txt
If it does not work for you, you may give easy_install a try:
    easy_install requirements.txt
    (or easy_install-2.7 requirements.txt)
Please note that these commands may need extra-privileges.


DESCRIPTION

PASTA is another ssh traffic analyser.
As such, it analyses ssh connection in a capture file. Based on the traffic
patterns, information such as idle time or connection type are estimated.
See the DETAILED DESCRIPTION to get more precise information.


KNOWN BUGS

A bug in some modified versions of argparse are making the -s and -S options
non-exclusive. In that case, if they are used together, it would be as if -s
was not used. Same thing with -t and --csv.


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


HOW TO WRITE A NEW PLUGIN

You need to add two files in the plugins folder. Let say that your plugin
is called bolognese:
    - bolognese.py:     should inherit and implement the required methods of
                        one of the two classes defined plugins/__init__.py
                        (more informations in this file)
    - bolognese.plugin: metadatas of the plugin: at least something like
                            [Core]
                            Name = Bolognese
                            Module = bolognese ; name of the .py file
                            [Documentation]
                            Author = PastaLover
                            Version = 1
                            Description = Add some sauce to PASTA
