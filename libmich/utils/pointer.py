# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.3
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
# * File Name : utils/pointer.py
# * Created : 2014-10-06
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/
# export filter
__all__ = ['ptr']


class ptr(object):
    '''
    Emulates a struct pointer behaviour
    
    Takes an object (e.g. dict, class or instance) and an element of it,
    and returns object[element] or object.element when called.
    If object's element value is changed after creation of ptr, 
    change will be taken into account by ptr.
    
    It is recursive, making possible to handle ptr(ptr(ptr(..., ), ), )
    '''
    def __init__(self, object, element, default=None):
        if not isinstance(object, ptr) \
        and not hasattr(object, '__getitem__') \
        and not hasattr(object, '__getattribute__'):
            raise(Exception('ptr: invalid object %s' % object))
        self._object = object
        self._element = element
        self._default = default
    
    def __call__(self):
        if isinstance(self._object, ptr):
            obj = self._object()
        else:
            obj = self._object
        if hasattr(obj, '__getitem__'):
            try:
                return obj.__getitem__(self._element)
            except:
                return self._default
        elif hasattr(obj, '__getattribute__'):
            if self._element in obj.__dict__:
                return obj.__dict__[self._element]
            else:
                try:
                    return obj.__getattribute__(self._element)
                except:
                    return self._default
    
    def __repr__(self):
        return 'ptr: %s' % self()
