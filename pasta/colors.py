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



import logging

class Colors:
    """Basic codes for colors"""
    FBla = FBlu = FCya = FGre = FMag = FRed = FRes = FWhi = FYel = ''
    BBla = BBlu = BCya = BGre = BMag = BRed = BRes = BWhi = BYel = ''


def Coloramaze():
    logger = logging.getLogger('Colors')
    try:
        import colorama
    except ImportError:
        logger.warning('Failed to import colorama')
    else:
        logger.info('Using colorama colors')
        colorama.init(autoreset=True)
        Colors.FBla = colorama.Fore.BLACK
        Colors.FBlu = colorama.Fore.BLUE
        Colors.FCya = colorama.Fore.CYAN
        Colors.FGre = colorama.Fore.GREEN
        Colors.FMag = colorama.Fore.MAGENTA
        Colors.FRed = colorama.Fore.RED
        Colors.FRes = colorama.Fore.RESET
        Colors.FWhi = colorama.Fore.WHITE
        Colors.FYel = colorama.Fore.YELLOW
        Colors.BBla = colorama.Back.BLACK
        Colors.BBlu = colorama.Back.BLUE
        Colors.BCya = colorama.Back.CYAN
        Colors.BGre = colorama.Back.GREEN
        Colors.BMag = colorama.Back.MAGENTA
        Colors.BRed = colorama.Back.RED
        Colors.BRes = colorama.Back.RESET
        Colors.BWhi = colorama.Back.WHITE
        Colors.BYel = colorama.Back.YELLOW
