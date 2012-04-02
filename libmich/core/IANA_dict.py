# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.1 
# *
# * Copyright © 2011. Benoit Michau. France Telecom.
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
# * File Name : core/IANA_dict.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# test with the following:
# test = IANA_dict({1 : ('test 1', 't1'), 2 : ('test 2', 't2'), \
#                   8 : ('test 8', 't8'), 9 : 'test 9', 20: 'test 20'})

class IANA_dict(dict):
    '''
    Class to manage dictionnaries with integer as keys 
    and 2-tuples of string as items,
    such as IANA protocols parameters reference: http://www.iana.org/protocols/
    
    call it like this:
    IANA_dict( { integer : ("parameter name", "parameter abbreviation"), 
                 integer: "parameter name", ... } )
    '''
    
    def __init__(self, IANA_dict={}):
        '''
        initialize like a dict
        [+] if 'key' is not integer, raises error
        [+] if value 'value' is not string or 2-tuple of string, raises error
        [+] if value is string, transforms it in 2-tuple ("value", "")
            i.e. value must be ("value name", value abbreviation")
        '''
        # 1st: rearrange string item to 2-tuple of string
        items = dict.items(IANA_dict)
        for i in items:
            if type(i[1]) is str:
                dict.__setitem__( IANA_dict, i[0], (i[1], "") )
        
        # 2nd: verification: key is int / long, and item is 2-tuple of string
        items = dict.items(IANA_dict)
        for i in items:
            if type(i[0]) not in (int, long):
                raise KeyError('%s : key must be integer' % i[0])
            if type(i[1]) is not tuple or len(i[1]) != 2:
                raise ValueError('%s : value must be string or 2-tuple of ' \
                                 'string' % i[1])
        
        dict.update(self, IANA_dict)
    
    def __getitem__(self, key):
        '''
        Same as dict.__getitem__(key)
        [+] If 'key' is integer and does not exist,
            returns the item corresponding to the last existing key,
            except if key is over the last key.
        [+] If 'key' is string and exists as value (name or abbreviation),
            returns first key found corresponding to the value.
        '''
        values = []
        for e in self.values():
            for v in e:
                if type(v) is str and len(v) > 0:
                    values.append(v)
        
        if self.__contains__(key):
            return dict.__getitem__(self, key)[0]
        
        elif type(key) in (int, long) \
        and self.s_keys()[0] < key < self.s_keys().pop():
            i = 0
            while self.__contains__(key-i) is False: i += 1
            return dict.__getitem__(self, key-i)[0]
        
        elif type(key) is str and key in values:
            i = 0
            while key not in self.items()[i][1]: i += 1
            return self.items()[i][0]
        
        else: 
            try: return dict.__getitem__(self, key)
            except KeyError: return key
    
    def __setitem__(self, key, item):
        '''
        Same as dict.__setitem__(key)
        [+] If 'key' is not integer, raises error
        [+] If 'value' is not string or 2-tuple of strings, raises error
        '''
        if type(key) not in [int, long]:
            raise KeyError('%s : key must be integer' % key)
        if type(item) is str:
            item = (item, "")
        if type(item) is not tuple or len(item) != 2:
            raise ValueError('%s : value must be string or 2-tuple of '\
                             'string' % item)
        dict.__setitem__(self, key, item)
    
    def s_keys(self):
        '''
        returns a sorted list of keys
        ''' 
        s_keys = dict.keys(self)
        s_keys.sort()
        return s_keys
    
    def items(self):
        '''
        returns the list of (key, value), following the order of sorted keys.
        '''
        items = []
        s_keys = self.s_keys()
        for k in s_keys:
            items.append( (k, dict.__getitem__(self, k)) )
        return items
#

