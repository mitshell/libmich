# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2014. Benoit Michau. ANSSI.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation. 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details. 
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : utils/repr.py
# * Created : 2014-09-26
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

# hexa / bin facilities
def bin(element):
    if hasattr(element, '__bin__'):
        return element.__bin__()
    elif isinstance(element, str):
        return ''.join(map(lambda b:'0'*(8-len(bin(b)[2:]))+bin(b)[2:], 
                           map(ord, element)))
    return __builtins__['bin'](element)

def hex(element):
    if hasattr(element, '__hex__'):
        return element.__hex__()
    elif isinstance(element, str):
        return ''.join(map(lambda x:hex(x)[2:], map(ord, element)))
    return __builtins__['hex'](element)

def hexgroup(element, group=4):
    h = hex(element)
    hr = [h[i:i+8] for i in range(0, len(h), 8)]
    return ['.'.join(hr[i:i+group]) for i in range(0, len(hr), group)]

# printing facilities
def show(element, with_trans=False):
    if hasattr(element, 'show'):
        print('%s' % element.show(with_trans))
    else:
        print('%s' % element)

def showattr(element):
    if hasattr(element, 'showattr'):
        print('%s' % element.showattr())

def hexview(element):
    print('\n'.join(hexgroup(element, 4)))

