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
# * File Name : asn1/ASN1.py
# * Created : 2014-10-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

try:
    from libmich.core.element import Layer
except:
    log('libmich module unavailable: encoding / decoding will not work')
else:
    Layer._byte_aligned = False
from utils import *
import parsers


#------------------------------------------------------------------------------#
# ASN.1 object common handler
#------------------------------------------------------------------------------#
class ASN1Obj(object):
    '''
    All ASN.1 objects (type, value, set, class, class_value, class_set,
    but also constructed types' components and subclasses' fields)
    are represented by an ASN1Obj instance. It has the following attributes:
    
    - name: str, or None; the identity of the ASN.1 object.
        Name can be None for ASN1 types used inlined into user-defined objects,
        e.g. in SEQUENCE OF ASN1Obj.
    
    - mode: 0, 1 or 2; the type of the object.
        - 0: subtype or subclass
        - 1: value
        - 2: set
    
    - type: str; provides the ASN.1 basic type of the object.
        All ASN.1 basic types are defined with TYPE_* from utils.py.
    
    - param: OrderedDict, or None; lists the formal parameters for a type.
        Each item has the following format:
        {str (parameter name) : {'type': ASN1Obj or None (parameter governor),
                                 'ref': list of referrer}}
        Each referrer is a 2-tuple (list of (str or int), bool),
        with the path of the referrer, and the indication if a whole ASN1Obj
        is required (bool=True) or just a single value (bool=False).
    
    - tag: 3-tuple, or None; contains the explicit tagging of the ASN.1 type.
        It has the following format:
        (unsigned integer value,
         str (mode 'IMPLICIT' / 'EXPLICIT'),
         str (class 'CONTEXT-SPECIFIC' / 'PRIVATE' / 'APPLICATION' / 'UNIVERSAL'))
    
    - typeref: ASN1Obj, or None;  provides the subtype of the object in case 
        it derives from a user-defined one (and not a basic one).
        Typerefs are looked-up from GLOBAL.TYPE table.
    
    - parent: ASN1Obj, or None; list the names of the parent container.
        For constructed types, this is set for all components,
        for CLASS type, this is set for all fields.
        This keeps track of container for all ASN.1 internal definition processed.
    
    - cont: type-dependent; lists the ASN.1 object whole content.
        - NULL: None
        - BOOLEAN: None
        - INTEGER: OrderedDict (str (named number): int (value)) or None
        - ENUMERATED: OrderedDict (str (enum): int (index)) or None
        - BIT STRING: OrderedDict (str (named bit): int (position)) or None
        - OCTET STRING / PrintableString / IA5String / NumericString: None
        - OBJECT IDENTIFIER: None
        - SEQUENCE / SET / CHOICE: OrderedDict (str (name): ASN1Obj) or None
        - SEQUENCE OF / SET OF: ASN1Obj
        - CLASS: OrderedDict (str (name): ASN1Obj) or None
        - OPEN / ANY: None (cont is temporarily used when assigning an ASN1Obj 
            value to an OPEN / ANY object, to host the ASN1Obj instance with 
            its own value)
        - user-defined subtype: the content is processed to fill-in parameters' 
            referrers (see attribute 'param')
    
    - ext: list of list or str, or None; indicates the list of extended content
        by name in a nested way,
        it is only used for ENUMERATED and constructed types.
    
    - const: list of dict; lists all the constraints of the ASN.1 object.
        Each list element has the followinf format:
        {'text':str, 
         'type':str,
         'keys':list of str, ... 
         str from keys:type-dependent, ...}
        All ASN.1 constraints are defined with CONST_* from utils.py.
        The ones currently supported are:
        for INTEGER and all types with SIZE constraints:
        - SINGLE VALUE, with specific keys: ('val':int, 'ext':bool)
        - VALUE RANGE, with specific keys:
            ('lb':int or None, 'ub':int or None, 'ext':bool)
        for BIT STRING and OCTET STRING:
        - CONTAINING, with specific key: ('obj': ASN1Obj)
        for IA5String, PrintableString and NumericString:
        - FROM, with specific key: ('alpha': list of str of len 1)
        for all types (especially OPEN / ANY):
        - SET REFERENCE, with specific keys: ('obj': ASN1Obj, 'at':str or None)
    
    - val: type-dependent (single_value) or dict (values_set), or None;
        for single values:
            - NULL: None
            - BOOLEAN: bool
            - INTEGER: int
            - ENUMERATED: str
            - BIT STRING: 2-tuple (int (BE value), int (bit length)), 
                or ASN1Obj (according to CONTAINING constraint)
            - OCTET STRING: str, or ASN1Obj (according to CONTAINING constraint)
            - PrintableString / IA5String / NumericString: str
            - OBJECT IDENTIFIER: list of int
            - CHOICE: 2-tuple (str (name), single_value (type-dependent))
            - SEQUENCE / SET: dict {str (name): single_value (type-dependent)}
            - SEQUENCE OF / SET OF:  list of single_value (type-dependent)
            - CLASS: dict {str (name): single_value (type-dependent)}
            - OPEN / ANY: str or 2-tuple (str (ASN1Obj's name within GLOBAL.TYPE), 
                single_value (type-dependent))
        for values' set:
            Python dict {'root': list of single_value (type-dependent),
                         'ext': list of single_value (type-dependent) 
                                or empty list or None}
    
    - flags: dict, or None; lists the specific behavior of internal ASN1 objects
        within constructed types or classes.
        - OPTIONAL: None; when present, means optional
        - DEFAULT: single_value (type-dependent, see val); when present, 
            provides default value
        - UNIQUE: None; when present, means unique
    
    - group: int, or None; indicates the grouping of extended ASN1 objects
        within constructed types extension only.
    
    - syntax: OrderedDict {str (name): (str (syntax), list (optional group)},
        or None; used only for classes that have WITH SYNTAX directive.
    
    CHOICE, SEQUENCE, SET and CLASS objects have specific attributes,
    in addition:
    
    - root_comp: list of str, lists all root components by name
    
    - root_opt: list of str, lists all OPTIONAL and DEFAULT root components
        by name.
    
    - ext_flat: list of str, flattened list of extended components by name
        (built from ext attribute).
    
    - ext_group: dict {int: list of str}, referencing extended components
        by group:
        -1 is for stand-alone extension,
        0 and more are for group of extensions, to be sequenced
    
    - cont_tags: index of all possible tags for contained components
        for SEQUENCE:
        list of [ (2-tuple(tag class, tag value), list of str), ...]
        for CHOICE and SET:
        dict of { 2-tuple(tag class, tag value): str, ...}
    
    Moreover, when encoding / decoding ASN1Obj objects, the following attributes
    are used:
    
    - codec: ASN1Codec, or None; it is used to encode / decode the transfer
        messages.
    
    - msg: libmich Layer, or None; it stores the transfer message structure,
        ready to be sent over the wire.
    '''
    # this adds verbosity on encoding / decoding objects
    #_DEBUG = 1
    _DEBUG = 0
    # this adds controls when settings ASN.1 objects value manually
    _SAFE = True
    
    # when set, shuts down codec error and tries to return without error
    # (however, the message will certainly be malformed)
    _RAISE_SILENTLY = False
    # when set, returns the libmich message structure set in ._msg attribute
    # after encode()ing / decode()ing
    _RET_STRUCT = False
    
    # CODEC for encoding / decoding ASN.1 transfer messages
    CODEC = None
    
    # the following attributes are used to store 
    # textual assignment collected from the ASN.1 module:
    #_text_decl
    #_text_def
    
    # the following keywords are used to identify all ASN.1 object attributes
    KW = ('name', 'mode', 'parent', 'param', 'tag', 'type', 'typeref', 
          'cont', 'ext', 'const', 'val', 'flags', 'group', 'syntax')
    
    def __init__(self, name='', mode=0, type=None, parent=None, param=None):
        self._name = name
        self._mode = mode
        self._parent = parent
        self._param = param
        self._type = type
        self._tag = None
        self._typeref = None
        self._cont = None
        self._ext = None
        self._const = []
        self._val = None
        self._flags = None
        self._group = None
        self._syntax = None
    
    def __repr__(self):
        type = self._type
        if self._type in (TYPE_SEQ_OF, TYPE_SET_OF) and self._cont:
            type = '%s %s' % (type, self._cont._type)
        if self._parent and self._typeref:
            type = '[%s] %s' % (self._typeref._name, type)
        if self._val is not None:
            if self._mode in (0, 1):
                val = repr(self())
                if len(val) > 50:
                    val = val[:50] + ' ...'
            elif self._mode == 2:
                val = []
                if self._val['root'] is not None:
                    val.extend(self._val['root'])
                if self._val['ext'] is not None:
                    val.extend(self._val['ext'])
                val = '{%s}' % ', '.join(map(repr, val))
                if len(val) > 50:
                    val = val[:50] + ' ...}'
            return '<%s (%s %s): %s>' % (self.get_name(),
                                         type,
                                         ['type', 'value', 'set'][self._mode],
                                         val.replace('\n', ', '))
        else:
            return '<%s (%s %s)>' % (self.get_name(),
                                     type,
                                     ['type', 'value', 'set'][self._mode])
    
    #--------------------------------------------------------------------------#
    # value handling
    #--------------------------------------------------------------------------#
    #
    # read values from encoded / decoded ASN.1 types #
    #
    def __call__(self, *args):
        # a standard __call__() will return the value
        if self._type != TYPE_CLASS or len(args) == 0:
            return self._val
        # but a __call__() can also be used to filter values / set of CLASS
        if len(args) >= 1:
            name = args[0]
        if len(args) >= 2:
            val = args[1]
        else:
            val = None
        #
        if self._cont and name not in self._cont:
            if self._syntax and name not in self._syntax:
                raise(ASN1_OBJ('%s: undefined identifier %s' \
                      % (self.get_fullname(), name)))
            else:
                name = self._syntax[name]
        #
        if self._mode == 1:
            if val is None:
                # returns the value associated to the identifier                
                return self._val[name]
            elif val == self._val[name]:
                # returns the list of fields' value associated
                return self._val
            else:
                return None
        #
        # for object set, need to take care of all values from root and ext
        elif self._mode == 2:
            if val is None:
                values = []
                if self._val['root'] is not None:
                    values.extend([v[name] for v in self._val['root']])
                if self._val['ext'] is not None:
                    values.extend([v[name] for v in self._val['ext']])
                return values
            else:
                if self._val['root'] is not None:
                    for v in self._val['root']:
                        if v[name] == val:
                            return v
                elif self._val['ext'] is not None:
                    for v in self._val['ext']:
                        if v[name] == val:
                            return v
                return None
    
    #
    # write values to ASN.1 types, before encoding them #
    #
    def _val_basic_match_type(self, val):
        if self._type == TYPE_NULL:
            return val is None
        elif self._type == TYPE_BOOL:
            return val in (False, True)
        elif self._type == TYPE_INTEGER:
            return isinstance(val, (int, long))
        elif self._type == TYPE_ENUM:
            if self._cont is None:
                # empty ENUM ...
                return val is None
            else:
                return isinstance(val, str) and val in self._cont
        elif self._type == TYPE_BIT_STR:
            if isinstance(val, ASN1Obj):
                # WNG: the test for ASN1Obj type compliance toward CONTAINING
                # is done by _val_basic_in_const()
                return True
            return isinstance(val, (list, tuple)) and len(val) == 2 \
            and all([isinstance(v, (int, long)) and v >= 0 for v in val])
        elif self._type == TYPE_OCTET_STR:
            if isinstance(val, ASN1Obj):
                # WNG: the test for ASN1Obj type compliance toward CONTAINING
                # is done by _val_basic_in_const()
                return True
            return isinstance(val, str)
        elif self._type in (TYPE_IA5_STR, TYPE_PRINT_STR, TYPE_NUM_STR,
                            TYPE_VIS_STR):
            return isinstance(val, str)
        elif self._type == TYPE_OID:
            return isinstance(val, list) \
            and all([isinstance(v, (int, long)) and v >= 0 for v in val])
    
    def _val_basic_in_const(self, val):
        if self._type == TYPE_INTEGER:
            lb, ub, ext = self.get_const_int()
            if not ext:
                if ub is not None and val > ub:
                    raise(ASN1_OBJ('%s: INTEGER value overflow (MAX: %s): %s'\
                          % (self.get_fullname(), ub, val)))
                elif lb is not None and val < lb:
                    raise(ASN1_OBJ('%s: INTEGER value underflow (MIN: %s): %s'\
                          % (self.get_fullname(), lb, val)))
        elif self._type == TYPE_BIT_STR and isinstance(val, tuple):
            lb, ub, ext = self.get_const_int()
            if not ext:
                if ub is not None and val[1] > ub:
                    raise(ASN1_OBJ('%s: BIT STRING size overflow (MAX: %s): %s'\
                          % (self.get_fullname(), ub, val[1])))
                elif lb is not None and val[1] < lb:
                    raise(ASN1_OBJ('%s: BIT STRING size underflow (MIN: %s): %s'\
                          % (self.get_fullname(), lb, val[1])))
        elif self._type in (TYPE_OCTET_STR, TYPE_PRINT_STR, TYPE_IA5_STR, 
                            TYPE_NUM_STR, TYPE_VIS_STR) \
        and isinstance(val, str):
            lb, ub, ext = self.get_const_int()
            if not ext:
                if ub is not None and len(val) > ub:
                    raise(ASN1_OBJ('%s: %s size overflow (MAX: %s): %s'\
                          % (self.get_fullname(), self._type, ub, len(val))))
                elif lb is not None and len(val) < lb:
                    raise(ASN1_OBJ('%s: %s size underflow (MIN: %s): %s'\
                          % (self.get_fullname(), self._type, lb, len(val))))
        if self._type in (TYPE_BIT_STR, TYPE_OCTET_STR) \
        and isinstance(val, ASN1Obj):
            const = self.get_const_contain()
            if const is None:
                raise(ASN1_OBJ('%s: %s, invalid value, no CONTAINING constraint'\
                      % (self.get_fullname(), self._type)))
            # TODO: improve this check
            if const['obj']._typeref != val._typeref \
            and const['obj']._typeref != val._name:
                raise(ASN1_OBJ('%s: %s, invalid value for CONTAINING constraint'\
                      % (self.get_fullname(), self._type)))
    
    def _set_val_basic(self, val):
        if self._SAFE:
            # ensures val type is correct, and within constraints
            if not self._val_basic_match_type(val):
                raise(ASN1_OBJ('%s: invalid %s value: %s'\
                      % (self.get_fullname(), self._type, val)))
            self._val_basic_in_const(val)
        self._val = val
    
    def _set_val_open(self, val):
        if isinstance(val, str):
            # passing a raw string
            self._val = val
        elif isinstance(val, tuple) and len(val) == 2 and val[0] in GLOBAL.TYPE:
            # passing a reference to an ASN1Obj internal structure:
            # ASN1Obj name as val[0]
            # ASN1Obj value as val[1]
            self._cont = GLOBAL.TYPE[val[0]].clone_light()
            self._cont.set_val(val[1])
            self._val = (val[0], self._cont._val)
            self._cont._val = None
        #elif isinstance(self._cont, ASN1Obj):
        #    # using a fixed ASN1Obj set in the OPEN type
        #    self._cont.set_val(val)
        #    self._val = self._cont._val
        #    self._cont._val = None
        elif self._SAFE:
            raise(ASN1_OBJ('%s: invalid %s value: %s'\
                  % (self.get_fullname(), self._type, val)))
    
    def _set_val_cho(self, val):
        # CHOICE: (name, val)
        if self._SAFE:
            if (val is None and len(self._cont) != 0) \
            or (not isinstance(val, tuple) or len(val) != 2 \
             or val[0] not in self._cont):
                raise(ASN1_OBJ('%s: invalid CHOICE value type'\
                      % self.get_fullname()))
        if len(self._cont) > 0:
            cho = self._cont[val[0]]
            cho.set_val(val[1])
            self._val = (val[0], cho._val)
            cho._val = None
    
    def _set_val_seqof(self, val):
        # SEQ_OF, SET_OF: [val1, val2, ...]
        if self._SAFE:
            lb, ub, ext = self.get_const_int()
            if lb is not None and ub is not None and lb == ub == 0 \
            and val is not None:
                # 0-sized SEQUENCE OF / SET OF ...
                raise(ASN1_OBJ('%s: empty %s requires None value'\
                      % (self.get_fullname(), self._type)))
            if not isinstance(val, list):
                raise(ASN1_OBJ('%s: invalid %s value type'\
                      % (self.get_fullname(), self._type)))
            if ext is False and ub is not None and len(val) > ub:
                raise(ASN1_OBJ('%s: %s size overflow: %s'\
                      % (self.get_fullname(), self._type, len(val))))
        self._val = []
        for v in val:
            self._cont.set_val(v)
            self._val.append(self._cont._val)
        self._cont._val = None
    
    def _set_val_seq(self, val):
        if self._SAFE:
            if val is not None and (not isinstance(val, dict) \
             or not all([name in self._cont for name in val])):
                # there is an issue here with SEQUENCE including OPEN TYPE
                raise(ASN1_OBJ('%s: invalid SEQ / SET / CLASS value type'\
                          % self.get_fullname()))
        #
        #if val is not None:
        #    self._val = dict()
        self._val = dict()
        #
        # root components
        for name in self._root_comp:
            if self._SAFE:
                if name not in self._root_opt \
                and (val is None or name not in val):
                    # if a value is not set, needs to be OPTIONAL 
                    # or have DEFAULT
                    raise(ASN1_OBJ('%s: missing mandatory component: %s'\
                          % (self.get_fullname(), name)))
            #
            comp = self._cont[name]
            #
            if comp._type == TYPE_NULL:
                self._val[name] = None
            #
            elif val is not None:
                if name in val:
                    v = val[name]
                else:
                    if comp._flags is not None and FLAG_DEF in comp._flags:
                        v = comp._flags[FLAG_DEF]
                    else:
                        v = None
                if v is not None:
                    # filter value through the component's set_val() method
                    comp.set_val(v)
                    self._val[name] = comp._val
                    comp._val = None
        #
        # extended components
        if self._type == TYPE_CLASS or self._ext is None or val is None:
            return
        if self._SAFE:
            # ensure all grouped extensions are set together
            val_ext = [name for name in self._ext_flat if name in val]
            for name in val_ext:
                if self._cont[name]._group >= 0:
                    group = self._ext_group[self._cont[name]._group]
                    if not all([name in val_ext for name in group]):
                        raise(ASN1_OBJ('%s: missing grouped extension'\
                              % self.get_fullname()))
                    for g in group:
                        val_ext.remove(g)
        for name in self._ext_flat:
            if name not in val:
                # WNG: this is incorrect according to the specification
                # not to set mandatory extended component.
                # However, it should be manageable by the decoder on the other
                # side as it is an extended value, advertised through the 
                # bitmap header
                pass
            if name in val:
                if self._cont[name]._flags is not None \
                and FLAG_DEF in self._cont[name]._flags \
                and self._cont[name]._flags[FLAG_DEF] == val[name]:
                    # do not keep value when equal to DEFAULT one
                    # this is part of the CANONICAL aspect of ASN.1 encoders
                    pass
                else:
                    # filter value through the component's set_val() method
                    self._cont[name].set_val(val[name])
                    self._val[name] = self._cont[name]._val
                    self._cont[name]._val = None
    
    def _set_valset(self, val, dst=None):
        # val = {'root':[...], 'ext':None}
        if isinstance(val, (tuple, list)) and dst in ('root', 'ext'):
            if self._SAFE:
                # consider it is root or extended values only
                if not all([self._val_match_type(v) for v in val]):
                    raise(ASN1_OBJ('%s: invalid values\' set type: %s'\
                          % (self.get_fullname(), val)))
                if not all([self._val_in_const(v) for v in val]):
                    raise(ASN1_OBJ('%s: values\' set out of constraints: %s'\
                          % (self.get_fullname(), val)))
            if self._val is None:
                self._val = {'root':[], 'ext':None}
            self._val[dst] = val
        elif isinstance(val, dict) and len(val) <= 2:
            if 'root' in val:
                self._set_val(val['root'], dst='root')
            if 'ext' in val:
                self._set_val(val['ext'], dst='ext')
        else:
            raise(ASN1_OBJ('%s: invalid values\' set type: %s'\
                  % (self.get_fullname(), val)))
    
    def set_val(self, val):
        if isinstance(val, tuple) \
        and self._type in (TYPE_OID, TYPE_SEQ_OF, TYPE_SET_OF):
            # always work with list for multiples values
            val = list(val)
        elif isinstance(val, list) \
        and self._type in (TYPE_BIT_STR, TYPE_CHOICE):
            # always work with tuple for BIT STR and CHOICE
            val = tuple(val)
        if self._mode in (0, 1):
            if self._type == TYPE_CHOICE:
                self._set_val_cho(val)
            elif self._type in (TYPE_SEQ_OF, TYPE_SET_OF):
                self._set_val_seqof(val)
            elif self._type in (TYPE_SEQ, TYPE_SET, TYPE_CLASS):
                self._set_val_seq(val)
            elif self._type in (TYPE_OPEN, TYPE_ANY):
                self._set_val_open(val)
            else:
                self._set_val_basic(val)
        elif self._mode == 2:
            if isinstance(val, (tuple, list)):
                self._set_valset(val, 'root')
            else:
                self._set_valset(val, None)
    
    #--------------------------------------------------------------------------#
    # encoding / decoding
    #--------------------------------------------------------------------------#
    def encode(self, val=None, **kwargs):
        if self._RAISE_SILENTLY:
            RAISED.set = False
        if self._SAFE:
            if self.CODEC is None \
            or not hasattr(self.CODEC, '_name') \
            or self.CODEC._name not in ('PER', 'BER') \
            or not issubclass(self.CODEC, ASN1Codec):
                raise(ASN1_OBJ('%s: invalid encoder defined: %s' 
                      % (self.get_fullname(), self.CODEC)))
        if val is not None:
            self.set_val(val)
        self._encode(**kwargs)
        if self._RET_STRUCT:
            return self._msg
    
    def _encode(self, **kwargs):
        #self._msg = Layer(self._name)
        self._msg = Layer(self.get_name())
        #
        # do not encode ASN.1 objects which are set with their DEFAULT value
        if self._flags is not None and FLAG_DEF in self._flags \
        and self._val == self._flags[FLAG_DEF]:
            self._not_encoded = 1
            return
        #
        self._codec = self.CODEC()
        if self._RAISE_SILENTLY:
            if not RAISED.set:
                try:
                    self._codec.encode(self, **kwargs)
                except self.CODEC._enc_err:
                    RAISED.set = True
                    log('-- encoding error --')
        else:
            self._codec.encode(self, **kwargs)
        if self._DEBUG:
            log('encode: %s, ' % (self.get_fullname(), hex(self)))
    
    def decode(self, buf='', **kwargs):
        if self._RAISE_SILENTLY:
            RAISED.set = False
        if self._SAFE:
            if self.CODEC is None \
            or not hasattr(self.CODEC, '_name') \
            or self.CODEC._name not in ('PER', 'BER') \
            or not issubclass(self.CODEC, ASN1Codec):
                raise(ASN1_OBJ('%s: invalid decoder defined: %s' 
                      % (self.get_fullname(), self.CODEC)))
        buf = self._decode(buf, **kwargs)
        if self._RET_STRUCT:
            return self._msg
    
    def _decode(self, buf, **kwargs):
        #self._msg = Layer(self._name)
        self._msg = Layer(self.get_name())
        self._codec = self.CODEC()
        if self._RAISE_SILENTLY:
            if not RAISED.set:
                try:
                    buf = self._codec.decode(self, buf, **kwargs)
                except self.CODEC._dec_err:
                    RAISED.set = True
                    log('-- decoding error --')
        else:
            buf = self._codec.decode(self, buf, **kwargs)
        if self._DEBUG:
            log('decode: %s, %s' % (self.get_fullname(), self()))
        return buf
    #
    # forwading libmich methods to the _msg attribute
    #
    def __str__(self):
        if hasattr(self, '_msg'): return str(self._msg)
        else: return ''
    
    def __bin__(self):
        if hasattr(self, '_msg'): return self._msg.__bin__()
        else: return ''
    
    def __hex__(self):
        if hasattr(self, '_msg'): return self._msg.__hex__()
        else: return ''
    
    def show(self, *args, **kwargs):
        if hasattr(self, '_msg'): return self._msg.show()
        else: return ''
    
    #--------------------------------------------------------------------------#
    # content accessors
    #--------------------------------------------------------------------------#
    def __getitem__(self, kw):
        if kw in self.KW:
            return getattr(self, '_%s' % kw)
    
    def __setitem__(self, kw, arg):
        if kw in self.KW:
            return setattr(self, '_%s' % kw, arg)
    
    def get_parent_root(self):
        # returns the ultimate parent to the ASN1Obj
        Obj = self._parent
        if Obj is None:
            return None
        while Obj is not None:
            parent = Obj._parent
            if parent is None:
                return Obj
            else:
                Obj = parent
    
    def get_parent_path(self):
        # returns the selection path from the parent root to the ASN1Obj
        path = []
        son = self
        parent = son._parent
        while parent:
            if parent._type in (TYPE_SEQ_OF, TYPE_SET_OF):
                path.append( 'cont' )
            else:
                path.extend( [son._name, 'cont'] )
            son = parent
            parent = son._parent
        path.reverse()
        return path
    
    def get_tag(self):
        if self._tag is not None:
            return self._tag
        # if no tag is specially defined, returns the UNIVERSAL one
        # excepted for CHOICE, OPEN / ANY, which do not have any UNIVERSAL tag
        elif self._type in (TYPE_CHOICE, TYPE_OPEN, TYPE_ANY):
            return None
        else:
            return (TAG_UNIV_TYPETOVAL[self._type], TAG_EXPLICIT, TAG_UNIVERSAL)
    
    def get_tag_val(self):
        # return a 2-tuple of int (or None), for the setting of Tag in BER
        # (class, tag value)
        t = self.get_tag()
        if t is None:
            return None
        cla = TAG_CLASS_BER[t[2]]
        return cla, t[0]
    
    def get_param(self):
        # returns the parameters, which can be associated to the parent
        # and not the ASN1Obj itself
        if self._parent:
            return self.get_parent_root()['param']
        else:
            return self._param
    
    def get_name(self):
        if self._name is None:
            if self._typeref is not None and self._typeref._name is not None:
                name = '_item_%s' % self._typeref._name
            else:
                name = '_item_%s' % self._type
        else:
            name = self._name
        return name
    
    def get_fullname(self):
        if self._parent is None:
            return self.get_name()
        else:
           return '%s.%s' % (self._parent.get_fullname(), self.get_name())
    
    def get_typename(self):
        typeref = self._typeref
        if typeref is None:
            return self.get_name()
        while typeref:
            typeref_more = typeref._typeref
            if typeref_more is None:
                return typeref.get_name()
            else:
                typeref = typeref_more
    
    def get_const_int(self):
        if self._type == TYPE_INTEGER:
            lb, ub, ext = None, None, False
        elif self._type in (TYPE_BIT_STR, TYPE_OCTET_STR, TYPE_IA5_STR,
                            TYPE_PRINT_STR, TYPE_NUM_STR, TYPE_VIS_STR,
                            TYPE_SEQ_OF, TYPE_SET_OF):
            lb, ub, ext = 0, None, False
        else:
            return None, None, None
        if self._const:
            for const in self._const:
                if const['type'] == CONST_SINGLE_VAL:
                    return const['val'], const['val'], const['ext']
                elif const['type'] == CONST_VAL_RANGE:
                    return const['lb'], const['ub'], const['ext']
        return lb, ub, ext
    
    def get_const_ref(self):
        if self._const:
            for const in self._const:
                if const['type'] == CONST_SET_REF:
                    return const
        return None
    
    def get_const_contain(self):
        if self._const:
            for const in self._const:
                if const['type'] == CONST_CONTAINING:
                    return const
        return None
    
    def get_internals(self):
        ASN1ObjDict = {}
        for kw in self.KW:
            ASN1ObjDict[kw] = getattr(self, '_%s' % kw)
        return ASN1ObjDict
    
    def set_internals(self, ASN1Obj):
        for kw in self.KW:
            setattr(self, '_%s' % kw, ASN1Obj[kw])
    
    #--------------------------------------------------------------------------#
    # syntax parsers
    #--------------------------------------------------------------------------#
    # parameters
    def parse_param(self, text=''):
        return parsers.parse_param(self, text)
    
    # whole ASN.1 definition (tag, type, content / syntax, constraints, flags)
    def parse_definition(self, text=''):
        text = text.strip()
        text = self._parse_tag(text)
        text = self._parse_type(text)
        text = self._parse_content_dispatch(text)
        text = self._parse_constraint_dispatch(text)
        if self._parent and text:
            text = self._parse_flags(text)
        return text
    
    # tag
    def _parse_tag(self, text=''):
        return parsers.parse_tag(self, text)
    
    # type
    def _parse_type(self, text=''):
        return parsers.parse_type(self, text)
    
    # content / syntax dispatcher
    def _parse_content_dispatch(self, text=''):
        if not text:
            return ''
        elif self._typeref:
            if self._typeref._param:
                # user-defined sub-subtype with parameterization
                return self._parse_content_subtype(text)
            else:
                # there is no additional content possible when typeref is used
                return text
        elif self._type in (TYPE_NULL, TYPE_BOOL, TYPE_OID, TYPE_OPEN, TYPE_ANY,
                            TYPE_OCTET_STR, TYPE_PRINT_STR, TYPE_IA5_STR, 
                            TYPE_NUM_STR, TYPE_VIS_STR):
            # there is no content for those types
            return text
        elif self._type == TYPE_INTEGER:
            return self._parse_content_integer(text)
        elif self._type == TYPE_ENUM:
            return self._parse_content_enum(text)
        elif self._type == TYPE_BIT_STR:
            return self._parse_content_bitstr(text)
        elif self._type in (TYPE_CHOICE, TYPE_SEQ, TYPE_SEQ_OF, TYPE_SET,
                            TYPE_SET_OF):
            return self._parse_content_constructed(text)
        elif self._type == TYPE_CLASS:
            text = self._parse_content_class(text)
            return self._parse_syntax(text)
        else:
            raise(ASN1_PROC_NOSUPP('%s: unsupported content for ASN.1 type '\
                  '%s: %s' % (self.get_fullname(), self._type, text)))
    
    # content
    def _parse_content_subtype(self, text=''):
        return parsers.parse_content_subtype(self, text)
    
    def _parse_content_integer(self, text=''):
        return parsers.parse_content_integer(self, text)
    
    def _parse_content_enum(self, text=''):
        return parsers.parse_content_enum(self, text)
    
    def _parse_content_bitstr(self, text=''):
        return parsers.parse_content_bitstr(self, text)
    
    def _parse_content_constructed(self, text=''):
        text = parsers.parse_content_constructed(self, text)
        if self._type in (TYPE_SEQ, TYPE_SET, TYPE_CHOICE):
            self._build_constructed_rootext()
        return text
    
    def _build_constructed_rootext(self):
        # build _root_comp: a static list of root components
        if self._ext is not None:
            self._root_comp = [c for c in self._cont if c not in self._ext]
        else:
            self._root_comp = [c for c in self._cont]
        # build _root_opt: a static list of optional root components
        self._root_opt = []
        for name in self._root_comp:
            if self._cont[name]._flags is not None \
            and (FLAG_OPT not in self._cont[name]._flags \
             or FLAG_DEF not in self._cont[name]._flags):
                self._root_opt.append(name)
        # build _ext_flat: a static list of flattened extensions
        #       _ext_group: a static dict of {group : extensions}
        if self._ext is not None:
            self._ext_flat = flatten(self._ext)
            self._ext_group = {}
            for name in self._ext_flat:
                if self._cont[name]._group is not None:
                    if self._cont[name]._group not in self._ext_group:
                        self._ext_group[self._cont[name]._group] = []
                    self._ext_group[self._cont[name]._group].append(name)
        # build _cont_tag: a static dict of {tag : component}
        if self._type in (TYPE_SET, TYPE_CHOICE):
            self._cont_tags = {}
            self._build_set_cont_tags(self._cont_tags)
        elif self._type == TYPE_SEQ:
            self._cont_tags = []
            self._build_seq_cont_tags(self._cont_tags, None)
    
    def _build_set_cont_tags(self, tags={}, name_chain=[]):
        # _cont_tags is a dict
        # go over all components, and store each component's tag as key
        for name in self._cont:
            tag = self._cont[name].get_tag_val()
            if tag is None:
                if self._cont[name]._type == TYPE_CHOICE:
                    # for untagged CHOICE, store tags of CHOICE's components
                    self._cont[name]._build_set_cont_tags(tags,
                                                          name_chain+[name])
                elif self._cont[name]._type in (TYPE_OPEN, TYPE_ANY):
                    # for untagged OPEN / ANY types, use (-1, -1) as tag value
                    tag = (-1, -1)
                else:
                    raise(ASN1_PROC_TEXT('%s: untagged component %s' \
                          % (self.get_fullname(), name_chain+[name])))
            # no duplicated tags are allowed at all
            if tag is not None:
                if tag in tags:
                    raise(ASN1_PROC_TEXT('%s: duplicated tag %s for component %s'\
                          % (self.get_fullname(), tag, name_chain+[name])))
                tags[tag] = name_chain+[name]
    
    def _build_seq_cont_tags(self, tags=[], prev_opt=None, name_chain=[]):
        # _cont_tags is a list
        # go over all components, and store each component's tag
        for name in self._cont:
            tag = self._cont[name].get_tag_val()
            if tag is None:
                if self._cont[name]._type == TYPE_CHOICE:
                    # for untagged CHOICE, store tags of CHOICE's components
                    self._cont[name]._build_seq_cont_tags(tags,
                                                          prev_opt,
                                                          name_chain+[name])
                elif self._cont[name]._type in (TYPE_OPEN, TYPE_ANY):
                    # for untagged OPEN / ANY types, use (-1, -1) as tag value
                    tag = (-1, -1)
                else:
                    raise(ASN1_PROC_TEXT('%s: untagged component %s' \
                          % (self.get_fullname(), name_chain+[name])))
            # identical tag to previous component is not allowed
            # in case the previous one is OPTIONAL / DEFAULT
            if tag is not None:
                if tag == prev_opt:
                    raise(ASN1_PROC_TEXT('%s: duplicated tag %s for component %s'\
                          % (self.get_fullname(), tag, name_chain+[name])))
                tags.append( (tag, name_chain+[name]) )
                #
                if (self._cont[name]._flags is not None \
                 and (FLAG_OPT not in self._cont[name]._flags \
                   or FLAG_DEF not in self._cont[name]._flags)) \
                or (self._ext is not None and name in self._ext):
                    prev_opt = tag
                else:
                    prev_opt = None
    
    def _parse_content_class(self, text=''):
        text = parsers.parse_content_class(self, text)
        self._root_comp = self._cont.keys()
        self._root_opt = []
        return text
    
    # syntax
    def _parse_syntax(self, text=''):
        return parsers.parse_syntax(self, text)
    
    # constraints dispatcher
    def _parse_constraint_dispatch(self, text=''):
        if not text:
            return ''
        if self._typeref and self._typeref._parent \
        and self._typeref.get_parent_root()['type'] == TYPE_CLASS:
            # CLASS field with set reference constraint
            return self._parse_constraint_clafield(text)
        elif self._type == TYPE_INTEGER:
            return self._parse_constraint_integer(text)
        elif self._type in (TYPE_BIT_STR, TYPE_OCTET_STR, TYPE_PRINT_STR, 
                            TYPE_IA5_STR, TYPE_NUM_STR, TYPE_VIS_STR):
            return self._parse_constraint_str(text)
        return text
    
    # constraints
    def _parse_constraint_integer(self, text=''):
        return parsers.parse_constraint_integer(self, text)
    
    def _parse_constraint_str(self, text=''):
        return parsers.parse_constraint_str(self, text)
    
    def _parse_constraint_clafield(self, text=''):
        return parsers.parse_constraint_clafield(self, text)
    
    # flags
    def _parse_flags(self, text=''):
        # there is no flags outside of constructed types or class
        return parsers.parse_flags(self, text)
    
    # whole ASN.1 value / set
    def parse_value(self, text=''):
        text = text.strip()
        if not text:
            return ''
        if self._mode in (0, 1):
            if self._type == TYPE_NULL:
                return self._parse_value_null(text)
            elif self._type == TYPE_BOOL:
                return self._parse_value_bool(text)
            elif self._type == TYPE_INTEGER:
                return self._parse_value_integer(text)
            elif self._type == TYPE_ENUM:
                return self._parse_value_enum(text)
            elif self._type == TYPE_BIT_STR:
                return self._parse_value_bitstr(text)
            elif self._type in (TYPE_OCTET_STR, TYPE_IA5_STR, TYPE_PRINT_STR,
                                TYPE_NUM_STR, TYPE_VIS_STR):
                return self._parse_value_str(text)
            elif self._type == TYPE_OID:
                return self._parse_value_oid(text)
            elif self._type == TYPE_CLASS:
                return self._parse_value_class(text)
            elif self._type == TYPE_CHOICE:
                return self._parse_value_choice(text)
            else:
                # TODO: support constructed type value parsing
                raise(ASN1_PROC_NOSUPP('%s: unsupported ASN.1 value for type %s: %s'\
                      % (self.get_fullname(), self._type, text)))
            # ensures value fit within the given type
            self.set_val(self._val)
        elif self._mode == 2:
            return self.parse_set(text)
        # something went wrong
        raise(ASN1_PROC_TEXT)
    
    def _parse_value_null(self, text=''):
        return parsers.parse_value_null(self, text)
    
    def _parse_value_bool(self, text=''):
        return parsers.parse_value_bool(self, text)
    
    def _parse_value_integer(self, text=''):
        return parsers.parse_value_integer(self, text)
    
    def _parse_value_enum(self, text=''):
        return parsers.parse_value_enum(self, text)
    
    def _parse_value_bitstr(self, text=''):
        return parsers.parse_value_bitstr(self, text)
    
    def _parse_value_str(self, text=''):
        return parsers.parse_value_str(self, text)
    
    def _parse_value_oid(self, text=''):
        return parsers.parse_value_oid(self, text)
    
    def _parse_value_class(self, text=''):
        return parsers.parse_value_class(self, text)
    
    def _parse_value_choice(self, text=''):
        return parsers.parse_value_choice(self, text)
    
    def parse_set(self, text=''):
        return parsers.parse_set(self, text)
    
    #--------------------------------------------------------------------------#
    # deep copy recursive routine
    #--------------------------------------------------------------------------#
    # TODO: handle properly CLASS value / set
    
    def to_dict(self):
        ASN1ObjDict = { \
            'name':None,
            'mode':0,
            'parent':None,
            'param':None,
            'tag':None,
            'type':None,
            'typeref':None,
            'cont':None,
            'ext':None,
            'const':[],
            'val':None,
            'flags':None,
            'group':None,
            'syntax':None }
        #
        if self._name:
            ASN1ObjDict['name'] = str(self._name)
        if self._mode:
            ASN1ObjDict['mode'] = int(self._mode)
        ASN1ObjDict['type'] = str(self._type)
        if self._parent:
            # WNG: the parent is set by _from_dict_cont() as the parent object
            # because this is unpicklable (it references self -> infinite loop)
            pass
        if self._param:
            ASN1ObjDict['param'] = self._to_dict_param()
        if self._tag:
            ASN1ObjDict['tag'] = (int(self._tag[0]),
                                  str(self._tag[1]),
                                  str(self._tag[2]))
        if self._typeref:
            ASN1ObjDict['typeref'] = self._typeref.to_dict()
        if self._cont:
            ASN1ObjDict['cont'] = self._to_dict_cont()
        if self._ext:
            ASN1ObjDict['ext'] = self._to_dict_ext()
        if self._const:
            ASN1ObjDict['const'] = self._to_dict_const()
        if self._val:
            if self._mode in (0, 1):
                ASN1ObjDict['val'] = self._to_dict_val()
            elif self._mode == 2:
                ASN1ObjDict['val'] = self._to_dict_set()
        if self._flags:
            ASN1ObjDict['flags'] = self._to_dict_flags()
        if self._group:
            ASN1ObjDict['group'] = int(self._group)
        if self._syntax:
            ASN1ObjDict['syntax'] = OD( map(lambda x:(str(x[0]), str(x[1])), 
                                            self._syntax.items()) )
        return ASN1ObjDict
    
    def _to_dict_param(self):
        param_dict = OD()
        for param_name in self._param:
            if self._param[param_name]['type']:
                param_type_clone = self._param[param_name]['type'].to_dict()
            else:
                param_type_clone = None
            if self._param[param_name]['ref']:
                param_ref_clone = list()
                for (p, b) in self._param[param_name]['ref']:
                    param_ref_clone.append((self._to_dict_param_path(p), bool(b)))
            else:
                param_ref_clone = None
            param_dict[str(param_name)] = {'type':param_type_clone, 
                                           'ref':param_ref_clone}
        return param_dict
    
    def _to_dict_param_path(self, path):
        path_clone = []
        for p in path:
            if isinstance(p, str):
                path_clone.append(str(p))
            else:
                path_clone.append(int(p))
        return path_clone
    
    def _to_dict_cont(self):
        if self._type in (TYPE_INTEGER, TYPE_ENUM, TYPE_BIT_STR):
            cont_dict = OD()
            for name in self._cont:
                cont_dict[str(name)] = int(self._cont[name])
            return cont_dict
        elif self._type in (TYPE_CHOICE, TYPE_SEQ, TYPE_SET, TYPE_CLASS):
            cont_dict = OD()
            for name in self._cont:
                if isinstance(self._cont[name]._typeref, ASN1ObjSelf) \
                or self._cont[name]._typeref == self:
                    # special processing for self-referencing component
                    cont_dict[str(name)] = '_SELF_REF_'
                else:
                    cont_dict[str(name)] = self._cont[name].to_dict()
            return cont_dict
        elif self._type in (TYPE_SEQ_OF, TYPE_SET_OF):
            return self._cont.to_dict()
    
    def _to_dict_ext(self):
        ext_clone = []
        for e in self._ext:
            if isinstance(e, str):
                ext_clone.append(str(e))
            elif isinstance(e, (tuple, str)):
                ext_clone.append(map(str, e))
        return ext_clone
    
    def _to_dict_const(self):
        const_clone = list()
        for c in self._const:
            const_clone.append({'text': str(c['text'])})
            if 'type' in c:
                const_clone[-1]['type'] = str(c['type'])
                const_clone[-1]['keys'] = map(str, c['keys'])
                if c['type'] in (CONST_SINGLE_VAL, CONST_VAL_RANGE):
                    const_clone[-1].update( self._to_dict_const_int(c) )
                elif c['type'] == CONST_CONTAINING:
                    const_clone[-1]['ref'] = str(c['ref'])
                elif c['type'] == CONST_SET_REF:
                    const_clone[-1]['ref'] = str(c['ref'])
                    if c['at'] is not None:
                        const_clone[-1]['at'] = str(c['at'])
                    else:
                        const_clone[-1]['at'] = None
        return const_clone
    
    def _to_dict_const_int(self, const):
        const_int_clone = {}
        if 'val' in const:
            if const['val'] is not None:
                const_int_clone['val'] = int(const['val'])
            else:
                const_int_clone['val'] = None
        else:
            if const['lb'] is not None:
                const_int_clone['lb'] = int(const['lb'])
            else:
                const_int_clone['lb'] = None
            if const['ub'] is not None:
                const_int_clone['ub'] = int(const['ub'])
            else:
                const_int_clone['ub'] = None
        const_int_clone['ext'] = bool(const['ext'])
        return const_int_clone
    
    def _to_dict_val(self):
        if self._type == TYPE_BOOL:
            return bool(self._val)
        elif self._type == TYPE_INTEGER:
            return int(self._val)
        elif self._type == TYPE_ENUM:
            return str(self._val)
        elif self._type == TYPE_BIT_STR:
            if isinstance(self._val, tuple): 
                return (int(self._val[0]), int(self._val[1]))
            elif isinstance(self._val, ASN1Obj):
                return self._val.to_dict()
        elif self._type == TYPE_OCTET_STR:
            if isinstance(self._val, str):
                return str(self._val)
            elif isinstance(self._val, ASN1Obj):
                return self._val.to_dict()
        elif self._type in (TYPE_IA5_STR, TYPE_PRINT_STR, TYPE_NUM_STR,
                            TYPE_VIS_STR):
            return str(self._val)
        elif self._type == TYPE_OID:
            return [int(i) for i in self._val]
        elif self._type == TYPE_CHOICE:
            # use the content type chosen to produce the serialized value
            cont_t = self._cont[self._val[0]]
            assert( cont_t._val is None )
            cont_t._val = self._val[1]
            val = cont_t._to_dict_val()
            cont_t._val = None
            return (str(self._val[0]), val)
        elif self._type in (TYPE_SEQ, TYPE_SET, TYPE_CLASS):
            # use each component's type to produce the serialized value
            val = dict()
            for name in self._val:
                cont_t = self._cont[name]
                assert( cont_t._val is None )
                cont_t._val = self._val[name]
                val[str(name)] = cont_t._to_dict_val()
                cont_t._val = None
            return val
        elif self._type in (TYPE_SEQ_OF, TYPE_SET_OF):
            # use the component's type to produce all serialized values
            val = []
            cont_t = self._cont
            assert( cont_t._val is None )
            for v in self._val:
                cont_t._val = v
                val.append( cont_t._to_dict_val() )
            cont_t._val = None
            return val
        elif self._type in (TYPE_OPEN, TYPE_ANY):
            if isinstance(self._val, str):
                return str(self._val)
            elif isinstance(self._val, ASN1Obj):
                return self._val.to_dict()
    
    def _to_dict_set(self):
        # local copy of values' set
        val_root, val_ext = self._val['root'], self._val['ext']
        val_root_clone, val_ext_clone = [], None
        # use the ASN1Obj to serialize each value in the root / ext set
        for v in val_root:
            self._val = v
            val_root_clone.append( self._to_dict_val() )
        if val_ext is not None:
            val_ext_clone = []
            for v in val_ext:
                self._val = v
                val_ext_clone.append( self._to_dict_val() )
        # restore copies of values' set
        self._val = {'root':val_root, 'ext':val_ext}
        return {'root':val_root_clone, 'ext':val_ext_clone}
    
    def _to_dict_flags(self):
        flag_clone = {}
        if FLAG_UNIQ in self._flags:
            flag_clone[FLAG_UNIQ] = None
        if FLAG_OPT in self._flags:
            flag_clone[FLAG_OPT] = None
            return flag_clone
        elif FLAG_DEF in self._flags:
            # use the ASN1Obj to serialize the DEFAULT value
            val = self._val
            self._val = self._flags[FLAG_DEF]
            flag_clone[FLAG_DEF] = self._to_dict_val()
            self._val = val
            return flag_clone
    
    #--------------------------------------------------------------------------#
    # deep copy reverse recursive routine
    #--------------------------------------------------------------------------#
    # TODO: handle properly CLASS value / set
    
    def from_dict(self, ASN1ObjDict):
        self.__init__()
        if ASN1ObjDict['name']:
            self._name = str(ASN1ObjDict['name'])
        if ASN1ObjDict['mode']:
            self._mode = int(ASN1ObjDict['mode'])
        self._type = str(ASN1ObjDict['type'])
        if ASN1ObjDict['parent']:
            # WNG: the parent is set by _from_dict_cont() as the parent object
            # is unpicklable (it references self -> infinite loop)
            pass
        if ASN1ObjDict['param']:
            self._from_dict_param(ASN1ObjDict['param'])
        if ASN1ObjDict['tag']:
            self._tag = (int(ASN1ObjDict['tag'][0]),
                         str(ASN1ObjDict['tag'][1]),
                         str(ASN1ObjDict['tag'][2]))
        if ASN1ObjDict['typeref']:
            self._typeref = ASN1Obj()
            self._typeref.from_dict( ASN1ObjDict['typeref'] )
        if ASN1ObjDict['cont']:
            self._from_dict_cont( ASN1ObjDict['cont'] )
        if ASN1ObjDict['ext']:
            self._from_dict_ext( ASN1ObjDict['ext'] )
        if ASN1ObjDict['const']:
            self._from_dict_const( ASN1ObjDict['const'] )
        if ASN1ObjDict['val']:
            if self._mode == 1:
                self._from_dict_val( ASN1ObjDict['val'] )
            elif self._mode == 2:
                self._from_dict_set( ASN1ObjDict['val'] )
        if ASN1ObjDict['flags']:
            self._from_dict_flags( ASN1ObjDict['flags'] )
        if ASN1ObjDict['group']:
            self._group = int(ASN1ObjDict['group'])
        if ASN1ObjDict['syntax']:
            self._syntax = OD( map(lambda x:(str(x[0]), str(x[1])),
                                   ASN1ObjDict['syntax'].items()) )
        
    def _from_dict_param(self, DictParam):
        param_dict = OD()
        for param_name in DictParam:
            if DictParam[param_name]['type']:
                param_type_clone = ASN1Obj()
                param_type_clone.from_dict( DictParam[param_name]['type'] )
            else:
                param_type_clone = None
            if DictParam[param_name]['ref']:
                param_ref_clone = list()
                for (p, b) in DictParam[param_name]['ref']:
                    param_ref_clone.append((self._to_dict_param_path(p), bool(b)))
            else:
                param_ref_clone = None
            param_dict[str(param_name)] = {'type':param_type_clone,
                                           'ref':param_ref_clone}
        self._param = param_dict
    
    def _from_dict_cont(self, DictCont):
        if self._type in (TYPE_INTEGER, TYPE_ENUM, TYPE_BIT_STR):
            cont_dict = OD()
            for name in DictCont:
                cont_dict[str(name)] = int(DictCont[name])
            self._cont = cont_dict
        elif self._type in (TYPE_CHOICE, TYPE_SEQ, TYPE_SET, TYPE_CLASS):
            cont_dict = OD()
            for name in DictCont:
                cont_dict[str(name)] = ASN1Obj()
                if DictCont[name] == '_SELF_REF_':
                    cont_dict[name]._typeref = ASN1ObjSelf(name=self._name)
                    if self not in GLOBAL.SELF:
                        GLOBAL.SELF.append( self )
                else:
                    cont_dict[name].from_dict( DictCont[name] )
                    cont_dict[name]['parent'] = self
            self._cont = cont_dict
            if self._type in (TYPE_SEQ, TYPE_SET, TYPE_CHOICE):
                self._build_constructed_rootext()
            elif self._type == TYPE_CLASS:
                self._root_comp = self._cont.keys()
                self._root_opt = []
        elif self._type in (TYPE_SEQ_OF, TYPE_SET_OF):
            self._cont = ASN1Obj()
            self._cont.from_dict(DictCont)
            self._cont._parent = self
    
    def _from_dict_ext(self, DictExt):
        ext_clone = []
        for e in DictExt:
            if isinstance(e, str):
                ext_clone.append(str(e))
            elif isinstance(e, (tuple, list)):
                ext_clone.append(map(str, e))
        self._ext = ext_clone
    
    def _from_dict_const(self, DictConst):
        const_clone = list()
        for c in DictConst:
            const_clone.append({'text': str(c['text'])})
            if 'type' in c:
                const_clone[-1]['type'] = str(c['type'])
                const_clone[-1]['keys'] = map(str, c['keys'])
                if c['type'] in (CONST_SINGLE_VAL, CONST_VAL_RANGE):
                    const_clone[-1].update( self._to_dict_const_int(c) )
                elif c['type'] == CONST_CONTAINING:
                    const_clone[-1]['ref'] = str(c['ref'])
                elif c['type'] == CONST_SET_REF:
                    const_clone[-1]['ref'] = str(c['ref'])
                    if c['at'] is not None:
                        const_clone[-1]['at'] = str(c['at'])
                    else:
                        const_clone[-1]['at'] = None
        self._const = const_clone
    
    def _from_dict_val(self, DictVal):
        if self._type == TYPE_BOOL:
            self._val = bool(DictVal)
        elif self._type == TYPE_INTEGER:
            self._val = int(DictVal)
        elif self._type == TYPE_ENUM:
            self._val = str(DictVal)
        elif self._type == TYPE_BIT_STR:
            if isinstance(DictVal, tuple):
                self._val = (int(DictVal[0]), int(DictVal[1]))
            elif isinstance(DictVal, dict):
                self._val = ASN1Obj()
                self._val.from_dict(DictVal)
        elif self._type == TYPE_OCTET_STR:
            if isinstance(DictVal, str):
                self._val = str(DictVal)
            elif isinstance(DictVal, dict):
                self._val = ASN1Obj()
                self._val.from_dict( DictVal )
        elif self._type in (TYPE_IA5_STR, TYPE_PRINT_STR, TYPE_NUM_STR,
                            TYPE_VIS_STR):
            self._val = str(DictVal)
        elif self._type == TYPE_OID:
            self._val = [int(i) for i in DictVal]
        elif self._type == TYPE_CHOICE:
            # use the content type chosen to produce the serialized value
            cont_t = self._cont[DictVal[0]]
            assert( cont_t._val is None )
            cont_t._val = DictVal[1]
            val = cont_t._to_dict_val()
            cont_t._val = None
            self._val = (str(DictVal[0]), val)
        elif self._type in (TYPE_SEQ, TYPE_SET, TYPE_CLASS):
            # use the content types sequenced to produce the serialized values
            val = dict()
            for name in DictVal:
                cont_t = self._cont[name]
                assert( cont_t._val is None )
                cont_t._val = DictVal[name]
                val[str(name)] = cont_t._to_dict_val()
                cont_t._val = None
            self._val = val
        elif self._type in (TYPE_SEQ_OF, TYPE_SET_OF):
            # use the content type to produce each serialized value
            val = []
            cont_t = self._cont
            assert( cont_t._val is None )
            for v in DictVal:
                cont_t._val = v
                val.append( cont_t._to_dict_val() )
            cont_t._val = None
            self._val = val
        elif self._type in (TYPE_OPEN, TYPE_ANY):
            if isinstance(DictVal, str):
                self._val = str(DictVal)
            elif isinstance(DictVal, dict):
                self._val = ASN1Obj()
                self._val.from_dict( DictVal )
    
    def _from_dict_set(self, DictSet):
        val_root_clone, val_ext_clone = [], None
        # use the ASN1Obj to serialize each value in the root / ext set
        for v in DictSet['root']:
            self._val = v
            val_root_clone.append( self._to_dict_val() )
        if DictSet['ext'] is not None:
            val_ext_clone = []
            for v in DictSet['ext']:
                self._val = v
                val_ext_clone.append( self._to_dict_val() )
        self._val = {'root':val_root_clone, 'ext':val_ext_clone}
    
    def _from_dict_flags(self, DictFlags):
        if FLAG_UNIQ in DictFlags:
            self._flags = {FLAG_UNIQ:None}
        if FLAG_OPT in DictFlags:
            if self._flags is None:
                self._flags = {}
            self._flags[FLAG_OPT] = None
        elif FLAG_DEF in DictFlags:
            # use the ASN1Obj to serialize the DEFAULT value
            val = self._val
            self._val = DictFlags[FLAG_DEF]
            if self._flags is None:
                self._flags = {}
            self._flags[FLAG_DEF] = self._to_dict_val()
            self._val = val
    
    #--------------------------------------------------------------------------#
    # cloning recursive routine
    #--------------------------------------------------------------------------#
    def clone(self):
        # cloning loses all references to external objects (e.g. typeref,
        # global value / set, ...) as it is a complete hard copy of all objects
        clone = ASN1Obj()
        clone.from_dict( self.to_dict() )
        if clone._type in (TYPE_SEQ, TYPE_SET, TYPE_CHOICE):
            clone._build_constructed_rootext()
        elif clone._type == TYPE_CLASS:
            self._root_comp = self._cont.keys()
            self._root_opt = []
        return clone
    
    def clone_light(self):
        # cloning lightly keeps all references from the original ASN1Obj
        # until they are changed (rebounded) explicitly in the clone
        clone = ASN1Obj()
        clone._name = self._name
        clone._mode = self._mode
        clone._parent = self._parent
        clone._param = self._param
        clone._tag = self._tag
        clone._type = self._type
        clone._typeref = self._typeref
        clone._cont = self._cont
        clone._ext = self._ext
        clone._const = self._const
        clone._val = self._val
        clone._flags = self._flags
        clone._group = self._group
        clone._syntax = self._syntax
        if clone._type in (TYPE_SEQ, TYPE_SET, TYPE_CHOICE):
            clone._build_constructed_rootext()
        elif clone._type == TYPE_CLASS:
            self._root_comp = self._cont.keys()
            self._root_opt = []
        return clone
    
    def clone_const(self):
        # clone lightly the ASN1Obj, except for its constraints
        clone = self.clone_light()
        clone._from_dict_const( self._to_dict_const() )
        return clone

# this is a trick to handle ASN.1 object self-reference:
# only the name of the object is kept, so the original object can be retrieved 
# at runtime
# flag must be handle in the same way as ASN1Obj
class ASN1ObjSelf(ASN1Obj):
    def __init__(self, name=''):
        if not name:
            raise(ASN1_PROC('Invalid name for self-referencing object: %s'\
                  % name))
        self._name = name
        ASN1Obj.__init__(self)
        self._type = '_SELF_REF_'

# this is to encapsulate any ASN.1 CODEC
class ASN1Codec(object):
    _name = ''
    def encode(self, Obj, **kwargs):
        pass
    def decode(self, Obj, buf, **kwargs):
        pass
