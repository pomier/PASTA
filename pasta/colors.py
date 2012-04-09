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

FBla = FBlu = FCya = FGre = FMag = FRed = FRes = FWhi = FYel = ''
BBla = BBlu = BCya = BGre = BMag = BRed = BRes = BWhi = BYel = ''


def Coloramaze():
    """Enable color support"""
    logger = logging.getLogger('Colors')
    try:
        import colorama
    except ImportError:
        logger.warning('Failed to import colorama')
    else:
        logger.info('Using colorama colors')
        colorama.init(autoreset=True)
        global FBla, FBlu, FCya, FGre, FMag, FRed, FRes, FWhi, FYel
        global BBla, BBlu, BCya, BGre, BMag, BRed, BRes, BWhi, BYel
        FBla = colorama.Fore.BLACK
        FBlu = colorama.Fore.BLUE
        FCya = colorama.Fore.CYAN
        FGre = colorama.Fore.GREEN
        FMag = colorama.Fore.MAGENTA
        FRed = colorama.Fore.RED
        FRes = colorama.Fore.RESET
        FWhi = colorama.Fore.WHITE
        FYel = colorama.Fore.YELLOW
        BBla = colorama.Back.BLACK
        BBlu = colorama.Back.BLUE
        BCya = colorama.Back.CYAN
        BGre = colorama.Back.GREEN
        BMag = colorama.Back.MAGENTA
        BRed = colorama.Back.RED
        BRes = colorama.Back.RESET
        BWhi = colorama.Back.WHITE
        BYel = colorama.Back.YELLOW
