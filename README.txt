                             ____   _    ____ _____  _
                            |  _ \ / \  / ___|_   _|/ \
                            | |_) / _ \ \___ \ | | / _ \
                            |  __/ ___ \ ___) || |/ ___ \
                            |_| /_/   \_\____/ |_/_/   \_\
                         PASTA is another SSH traffic analyser



AUTHORS

The PASTA team:
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


KNOWN BUGS

A bug in some modified versions of argparse are making the -s and -S options
non-exclusive. In that case, if they are used together, it would be as if -s
is not used.


--
TODO: rest of the file (description of the software, requirements, how
      to use, install, explain that some connections can't be detected, etc)
      - may be done later
