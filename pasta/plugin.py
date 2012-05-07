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
How plugins interract with PASTA
"""

class Plugin:
    """Plugins should inherit this class"""

    DESCRIPTION = '' # Description Name

    def __init__(self, connections):
        """The constructor receives the connections"""
        self.connections = connections

    def compute(self):
        """Do all the computations"""
        pass

    def result(self):
        """Return the result of the computations as a string"""
        return ''