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
Define plugin interraction with PASTA

The plugins should inherit from a class of this file
"""

from yapsy.IPlugin import IPlugin


class SingleConnectionAnalyser(IPlugin):
    """Plugin which analyse a single connection"""

    def __init__(self):
        """Do not change this method, use activate instead"""
        IPlugin.__init__(self)

    def activate(self):
        """Activation of the plugin"""
        IPlugin.activate(self)

    def deactivate(self):
        """Deactivation of the plugin"""
        IPlugin.deactivate(self)

    def analyse(self, connection):
        """
        Get and analyse the connection

        Should raise a RuntimeWarning if the plugin can not work with this
        connection or if the plugin do not find anything interresting during
        the analyse
        """
        raise NotImplementedError()

    @staticmethod
    def result_fields():
        """Return the fields of the analyse as a tuple of strings"""
        raise NotImplementedError()

    def result_repr(self):
        """
        Return the result of the analyse as a dict of strings
        Note: only keys returned by fields will be considered
        """
        raise NotImplementedError()


class InterConnectionsAnalyser(IPlugin):
    """Plugin which analyse links between connections"""

    def __init__(self):
        """Do not change this method, use activate instead"""
        IPlugin.__init__(self)

    def activate(self):
        """Activation of the plugin"""
        IPlugin.activate(self)

    def deactivate(self):
        """Deactivation of the plugin"""
        IPlugin.deactivate(self)

    def analyse(self, connections):
        """
        Get and analyse the connections

        Should raise a RuntimeWarning if the plugin can not work with this
        connection or if the plugin do not find anything interresting during
        the analyse
        """
        raise NotImplementedError()

    def result_repr(self):
        """Return the result of the analyse as a string"""
        raise NotImplementedError()
