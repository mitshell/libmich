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
# * File Name : asn1/utils.py
# * Created : 2014-10-07
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import re
from struct import pack
from libmich.core.shtr import decompose

#------------------------------------------------------------------------------#
# library-wide Python routines
# and commodity function / classes
#------------------------------------------------------------------------------#
# commodity
def log(msg):
    '''
    customizable print function
    '''
    print(msg)


class OD(object):
    '''
    custom OrderedDict object, pickelable
    '''
    # pickeling routines
    #def __getnewargs__(self):
    #    return (self.items(), )
    
    def __getstate__(self):
        return (self._index, self._dict)
    
    def __setstate__(self, state):
        self._index = state[0]
        self._dict = state[1]
    
    # standard dict routines
    def __init__(self, items=[]):
        self._dict = {}
        self._index = []
        for k, v in items:
            self.__setitem__(k, v)
    
    def __repr__(self):
        return '\n'.join(['%s: %s' % (k, repr(self[k])) for k in self])
    
    def __len__(self):
        return len(self._index)
    
    def __getitem__(self, key):
        return self._dict.__getitem__(key)
    
    def __setitem__(self, key, val):
        self._dict.__setitem__(key, val)
        if key not in self._index:
            self._index.append(key)
    
    def __delitem__(self, key):
        self._dict.__delitem__(key)
        self._index.remove(key)
    
    def __iter__(self):
        return self._index.__iter__()
    
    def clear(self):
        self._dict.clear()
        self._index = []
    
    def keys(self):
        return self._index
    
    def items(self):
        return [(k, self._dict[k]) for k in self._index]
    
    def values(self):
        return [self._dict[k] for k in self._index]

def export(scope):
    '''
    export the GLOBAL tables into the given scope
    e.g.
    >>> export(globals())
    to get all ASN.1 objects within the interpreter scope
    '''
    for name in GLOBAL.TYPE:
        scope[name.replace('-', '_')] = GLOBAL.TYPE[name]
    for name in GLOBAL.VALUE:
        scope[name.replace('-', '_')] = GLOBAL.VALUE[name]
    for name in GLOBAL.SET:
        scope[name.replace('-', '_')] = GLOBAL.SET[name]

#------------------------------------------------------------------------------#
# ASN1-wide Python exceptions
#------------------------------------------------------------------------------#
# for generic ASN.1 errors when processing ASN.1 files
class ASN1_PROC(Exception): pass
# for ASN.1 features not supported by the processor
class ASN1_PROC_NOSUPP(Exception): pass
# for error detected by the processor while parsing ASN.1 syntax
class ASN1_PROC_TEXT(Exception): pass
# for error in resolving references to ASN.1 objects
class ASN1_PROC_LINK(Exception): pass
# for error when manipulating ASN1Obj
class ASN1_OBJ(Exception): pass
# for all ASN.1 codec error
class ASN1_CODEC(Exception): pass

# this is to support _RAISE_SILENTLY
class RAISED:
    set = False

#------------------------------------------------------------------------------#
# library-wide Python global objects
#------------------------------------------------------------------------------#

# global configuration options set from the module header
class MODULE_OPT(object):
    # tagging mode: default is EXPLICIT mode (also when not set)
    TAG = 'EXPLICIT' # 'EXPLICIT', 'IMPLICIT', 'AUTOMATIC'
    # extensibility mode: can be implied, or not
    EXT = None # None, 'IMPLIED'

# GLOBAL: specific ASN.1 global tables
def _make_GLOBAL():
    
    class GLOBAL(object):
        #
        # stores all user-defined ASN.1 subtypes
        TYPE = OD()
        # stores all user-defined ASN.1 values and sets
        VALUE = OD()
        SET = OD()
        #
        # for all ASN.1 initialized objects that are user-defined but
        # still needs to be processed
        OBJ = []
        # for ASN.1 initialized objects that are user-defined and have a component
        # that is self-referencing, and needs to be re-processed afterwards
        SELF = []
        
        @classmethod
        def clear(cla):
            cla.TYPE.clear()
            cla.VALUE.clear()
            cla.SET.clear()
            cla.clear_tmp()
        
        @classmethod
        def clear_tmp(cla):
            del cla.OBJ[:]
            del cla.SELF[:]
    
    return GLOBAL

GLOBAL = _make_GLOBAL()

# list ASN.1 ISO OID required to be known by the compiler
ASN1_OID_ISO = {
    'itu-t':0,
    'ccitt':0,
    'recommendation':0,
    'question':1,
    'administration':2,
    'network-operator':3,
    'identified-organization':4,
    'iso':1,
    'standard':0,
    'member-body':2,
    'identified-organization':3,
    'joint-iso-itu-t':2,
    'joint-iso-ccitt':2
    }

###
# DO NOT CHANGE the following identifiers
# as many of them correspond directly to the ASN.1 syntax
###
# basic types
TYPE_NULL           = 'NULL'
TYPE_BOOL           = 'BOOLEAN'
TYPE_OID            = 'OBJECT IDENTIFIER'
TYPE_INTEGER        = 'INTEGER'
TYPE_REAL           = 'REAL'
TYPE_ENUM           = 'ENUMERATED'
TYPE_BIT_STR        = 'BIT STRING'
TYPE_OCTET_STR      = 'OCTET STRING'
TYPE_IA5_STR        = 'IA5String'
TYPE_PRINT_STR      = 'PrintableString'
TYPE_NUM_STR        = 'NumericString'
TYPE_VIS_STR        = 'VisibleString'
# constructed types
TYPE_CHOICE         = 'CHOICE'
TYPE_SEQ            = 'SEQUENCE'
TYPE_SEQ_OF         = 'SEQUENCE OF'
TYPE_SET            = 'SET'
TYPE_SET_OF         = 'SET OF'
# wrapper types
TYPE_OPEN           = 'OPEN_TYPE'
TYPE_ANY            = 'ANY'
TYPE_EXT            = 'EXTERNAL'
# info object
TYPE_CLASS          = 'CLASS'
#
TYPE_CONSTRUCTED    = (TYPE_CLASS, TYPE_CHOICE, TYPE_SEQ, 
                       TYPE_SEQ_OF, TYPE_SET, TYPE_SET_OF)

# tag type listing
TAG_IMPLICIT        = 'IMPLICIT'
TAG_EXPLICIT        = 'EXPLICIT'
TAG_AUTO            = 'AUTOMATIC'
TAG_CONTEXT_SPEC    = 'CONTEXT-SPECIFIC'
TAG_PRIVATE         = 'PRIVATE'
TAG_APPLICATION     = 'APPLICATION'
TAG_UNIVERSAL       = 'UNIVERSAL'
#
TAG_CLASS_BER = {
    TAG_UNIVERSAL : 0,
    TAG_APPLICATION : 1,
    TAG_CONTEXT_SPEC : 2,
    TAG_PRIVATE : 3
}
#
TAG_UNIV_TYPETOVAL = {
    TYPE_BOOL : 1,
    TYPE_INTEGER : 2,
    TYPE_BIT_STR : 3,
    TYPE_OCTET_STR : 4,
    TYPE_NULL : 5,
    TYPE_OID : 6,
    TYPE_EXT: 8,
    TYPE_REAL : 9,
    TYPE_ENUM : 10,
    TYPE_SEQ : 16,
    TYPE_SEQ_OF : 16,
    TYPE_SET : 17,
    TYPE_SET_OF : 17,
    TYPE_NUM_STR : 18,
    TYPE_PRINT_STR : 19,
    TYPE_IA5_STR : 22,
    TYPE_VIS_STR : 26
}
TAG_UNIV_VALTOTYPE = {
    0 : 'reserved for BER',
    1 : TYPE_BOOL,
    2 : TYPE_INTEGER,
    3 : TYPE_BIT_STR,
    4 : TYPE_OCTET_STR,
    5 : TYPE_NULL,
    6 : TYPE_OID,
    7 : 'ObjectDescriptor',
    8 : TYPE_EXT,
    9 : TYPE_REAL, # actually unsupported, yet
    10 : TYPE_ENUM,
    11 : 'EMBEDDED PDV', 
    12 : 'UTF8String',
    13 : 'RELATIVE-OID',
    14 : 'reserved ffu',
    15 : 'reserved ffu',
    16 : TYPE_SEQ, # but also TYPE_SEQ_OF
    17 : TYPE_SET, # but also TYPE_SET_OF
    18 : TYPE_NUM_STR,
    19 : TYPE_PRINT_STR,
    20 : 'TeletexString',
    21 : 'VideotexString',
    22 : TYPE_IA5_STR,
    23 : 'UTCTime',
    24 : 'GeneralizedTime',
    25 : 'GraphicString',
    26 : TYPE_VIS_STR,
    27 : 'GeneralString',
    28 : 'UniversalString',
    29 : 'CHARACTER STRING',
    30 : 'BMPString',
    31 : 'reserved ffu'
}

# constraints type listing
CONST_SINGLE_VAL    = 'CONST_SINGLE_VAL' # keys: ('val':int, 'ext':bool)
CONST_VAL_RANGE     = 'CONST_VAL_RANGE' # keys: ('lb':int, 'ub':int, 'ext':bool)
CONST_CONTAINING    = 'CONST_CONTAINING' # keys: ('obj':ASN1Obj)
CONST_SET_REF       = 'CONST_SET_REF' # keys: ('obj':ASN1Obj, 'at':str)
CONST_ALPHABET      = 'CONST_ALPHABET' # keys: ('alpha': list)
# constraints parsed but ignored at runtime
CONST_CONST_BY      = 'CONST_CONST_BY' # keys: None
# constraints unsupported (currently not used)
CONST_TYPE_INCL     = 'CONST_TYPE_INCL'
CONST_REGEXP        = 'CONST_REGEXP'
CONST_ENCODE_BY     = 'CONST_ENCODE_BY'

# specific flags
FLAG_OPT            = 'OPTIONAL'
FLAG_DEF            = 'DEFAULT'
FLAG_UNIQ           = 'UNIQUE'

#------------------------------------------------------------------------------#
# regexp processing routines
#------------------------------------------------------------------------------#

# basic ASN.1 tokens
_RE_INTEGER = '(?:\-{0,1}0{1})|(?:\-{0,1}[1-9]{1}[0-9]{0,})'
_RE_INTEGER_POS = '(?:\-{0,1}0{1})|(?:[1-9]{1}[0-9]{0,})'
_RE_IDENT = '[a-z]{1,}[a-zA-Z0-9\-]{0,}'
_RE_TYPEREF = '[A-Z]{1,}[a-zA-Z0-9\-]{0,}'
SYNT_RE_IDENT = re.compile( \
    '(?:^|\s{1})(%s)' % _RE_IDENT)
SYNT_RE_FIELD_IDENT = re.compile( \
    '(?:^|\s{1})\&([a-zA-Z0-9\-]{1,})')
SYNT_RE_TYPEREF = re.compile( \
    '(?:^|\s{1})(%s)' % _RE_TYPEREF)
SYNT_RE_CLASSREF = re.compile( \
    '(?:^|\s{1})((%s)\s{0,}\.\&([a-zA-Z0-9\-]{1,}))' % _RE_TYPEREF)
SYNT_RE_REMAINING = re.compile( \
    '[a-zA-Z0-9\(\)\[\{\}\-\!\.\:\?\^\&,;]')

# useful ASN.1 tokens
SYNT_RE_MODULEREF = re.compile( \
    '(?:^|\s{1})(%s){1}\s{0,}(\{[\s\-a-zA-Z0-9\(\)]{1,}\}){0,1}' % _RE_TYPEREF)
SYNT_RE_MODULEFROM = re.compile( \
    '(?:FROM\s{1,})(%s){1}\s{0,}(\{[\s\-a-zA-Z0-9\(\)]{1,}\}){0,1}' % _RE_TYPEREF)
SYNT_RE_TAG = re.compile( \
    '\[\s{0,}(UNIVERSAL|APPLICATION|PRIVATE){0,1}\s{0,}(?:(%s)|(%s))\s{0,}\]'\
    % (_RE_INTEGER_POS, _RE_IDENT))
SYNT_RE_PARAM = re.compile( \
    '(%s)(?:\s{0,}\:\s{0,}(%s|%s)){0,1}' % (_RE_TYPEREF, _RE_IDENT, _RE_TYPEREF))
SYNT_RE_ARGPASS = re.compile( \
    '\{\s{0,}(%s)|(%s)\s{0,}\}' % (_RE_IDENT, _RE_TYPEREF))
SYNT_RE_INT_ID = re.compile( \
    '(%s)\s{0,}\(\s{0,}((%s)|(%s))\s{0,}\)' % (_RE_IDENT, _RE_INTEGER, _RE_IDENT))
SYNT_RE_ENUM = re.compile( \
    '(%s|\.{3})\s{0,}(?:\(\s{0,}((%s)|(%s))\s{0,}\)){0,1}'\
    % (_RE_IDENT, _RE_INTEGER_POS, _RE_IDENT))
SYNT_RE_OID_COMP = re.compile( \
    '(%s)|((%s)\s{0,}(?:\((%s)\)){0,1})' % (_RE_INTEGER_POS, _RE_IDENT, _RE_INTEGER_POS))
SYNT_RE_SINGLE_VAL = re.compile( \
    '(%s)|(%s)' % (_RE_INTEGER, _RE_IDENT))
SYNT_RE_VAL_RANGE = re.compile( \
    '((%s)|(%s)|(MIN))\s{0,}(\.{2})\s{0,}((%s)|(%s)|(MAX))'\
    % (_RE_INTEGER, _RE_IDENT, _RE_INTEGER, _RE_IDENT))
SYNT_RE_SET_REF = re.compile( \
    '\{(%s)\}(?:\{@(%s)\}){0,1}' % (_RE_TYPEREF, _RE_IDENT))
SYNT_RE_SET_REF_EXT = re.compile( \
    '(?:^\!\s{0,})(?:(%s)\s{0,}\:\s{0,}(%s))' % (_RE_TYPEREF, _RE_IDENT))
SYNT_RE_PARAM_ARG = re.compile( \
    '(%s|%s|%s)|(?:\{\s{0,}(%s)\s{0,}\})'\
    % (_RE_INTEGER, _RE_IDENT, _RE_TYPEREF, _RE_TYPEREF))
SYNT_RE_SET_ELT = re.compile( \
    '(?:^\s{0,})(?:(%s)|(%s))(?:\s{0,}$)' % (_RE_TYPEREF, _RE_IDENT))
SYNT_RE_CONTAINING = re.compile( \
    '(?:^\s{0,})(?:CONTAINING\s{1,}(%s))(?:\s{0,}$)' % (_RE_TYPEREF))
SYNT_RE_CONSTRAINED_BY = re.compile( \
    '(?:^\s{0,})(?:CONSTRAINED\s{1,}BY)')
SYNT_RE_FLAG = re.compile('(?:^\s{0,})(OPTIONAL|UNIQUE|DEFAULT)')
SYNT_RE_ALPHABET_LETTER = re.compile('^(?:\"(.)\"\|){0,}?(?:\"(.)\"){1}$')
SYNT_RE_ALPHABET_WORD = re.compile('^\"(.*)\"$')

# list of all ASN.1 keywords
SYNT_KEYWORDS = [ \
'ABSENT', 'ABSTRACT-SYNTAX', 'ALL', 'APPLICATION', 'AUTOMATIC', 'BEGIN',
'BIT', 'BMPString', 'BOOLEAN', 'BY', 'CHARACTER', 'CHOICE', 'CLASS', 'COMPONENT',
'COMPONENTS', 'CONSTRAINED', 'CONTAINING', 'DEFAULT', 'DEFINITIONS', 'EMBEDDED',
'ENCODED', 'END', 'ENUMERATED', 'EXCEPT', 'EXPLICIT', 'EXPORTS', 'EXTENSIBILITY',
'EXTERNAL', 'FALSE', 'FROM', 'GeneralizedTime', 'GeneralString', 'GraphicString',
'IA5String', 'IDENTIFIER', 'IMPLICIT', 'IMPLIED', 'IMPORTS', 'INCLUDES', 'INSTANCE',
'INTEGER', 'INTERSECTION', 'ISO646String', 'MAX', 'MIN', 'MINUS-INFINITY',
'NULL', 'NumericString', 'OBJECT', 'ObjectDescriptor', 'OCTET', 'OF', 'OPTIONAL',
'PATTERN', 'PDV', 'PLUS-INFINITY', 'PRESENT', 'PrintableString', 'PRIVATE',
'REAL', 'RELATIVE-OID', 'SEQUENCE', 'SET', 'SIZE', 'STRING', 'SYNTAX', 'T61String',
'TAGS', 'TeletexString', 'TRUE', 'TYPE-IDENTIFIER', 'UNION', 'UNIQUE', 'UNIVERSAL',
'UniversalString', 'UTCTime', 'UTF8String', 'VideotexString', 'VisibleString',
'WITH']

# list of all ASN.1 basic types and class
SYNT_BASIC_TYPES = [ \
'BOOLEAN', 'NULL', 'INTEGER', 'ENUMERATED', 'REAL', 'BIT STRING', 'OCTET STRING',
'OBJECT IDENTIFIER', 'RELATIVE-OID',
'NumericString', 'PrintableString', 'VisibleString', 'ISO646String', 'IA5String',
'TeletexString', 'T61String', 'VideotexString', 'GraphicString', 'GeneralString',
'UniversalString', 'BMPString', 'UTF8String', 'ObjectDescriptor', 'GeneralizedTime',
'UTCTime',
'SEQUENCE', 'SEQUENCE OF', 'SET', 'SET OF', 'CHOICE',
'EXTERNAL', 'EMBEDDED PDV', 'CHARACTER STRING',
'CLASS', 'ANY', 'OPEN_TYPE']

# list of all ASN.1 keywords that cannot be used in a WITH SYNTAX statement
SYNT_SYNTAX_BL = [ \
'BIT', 'BOOLEAN', 'CHARACTER', 'CHOICE', 'EMBEDDED', 'END', 'ENUMERATED', 
'EXTERNAL', 'FALSE', 'INSTANCE', 'INTEGER', 'INTERSECTION', 'MINUS-INFINITY', 
'NULL', 'OBJECT', 'OCTET', 'PLUS-INFINITY', 'REAL', 'RELATIVE-OID', 'SEQUENCE', 
'SET', 'TRUE', 'UNION']

def match_basic_type(text=''):
    for t in SYNT_BASIC_TYPES:
        if t == text[:len(t)]:
            return t
    return None

#------------------------------------------------------------------------------#
# text processing routines
#------------------------------------------------------------------------------#

stripper = lambda x:x.strip()

def scan_for_comment(text=''):
    '''
    returns a list of 2-tuple for each ASN.1 comment {start offset, end offset}
    '''
    ret = []
    comment = False
    cur = 0
    while cur < len(text):
        if text[cur:cur+2] == '--':
            if not comment:
                # comment starting
                comment = True
                start = cur
                # exception for full line of ------------------ sh*t
                eol = text[cur:].find('\n')
                if eol > 2 and text[cur:cur+eol] == eol*'-':
                    ret.append( (start, start+eol) )
                    comment = False
                    cur += eol
                else:
                    cur += 2
            else:
                # comment ending
                comment = False
                stop = cur+2
                ret.append( (start, stop) )
                cur += 2
        elif text[cur:cur+1] == '\n' and comment:
            # end-of-line, comment ending
            comment = False
            stop = cur
            ret.append( (start, stop) )
            cur += 1
        else:
            cur += 1
    return ret

def clean_text(text=''):
    '''
    removes ASN.1 comments
    replaces \t with space
    removes duplicated spaces
    '''
    # remove comments
    comments = scan_for_comment(text)
    comments.reverse()
    if len(comments):
        for (c_start, c_stop) in comments:
            text = text[:c_start] + text[c_stop:]
    # replace tab
    text = text.replace('\t', ' ')
    # remove duplicated spaces
    text = re.sub(' {2,}', ' ', text)
    #
    return text


def search_top_lvl_sep(text='', sep=','):
    '''
    returns a list of offsets for each top-level separator found in the text
    '''
    ret = []
    #
    count = {'(':0, ')':0, '{':0, '}':0, '[':0, ']':0}
    is_top_lvl = lambda c: c['(']==c[')'] and c['{']==c['}'] and c['[']==c[']']
    #
    for cur in range(len(text)):
        if text[cur] in count:
            count[text[cur]] += 1
        if text[cur] == sep and is_top_lvl(count):
            ret.append(cur)
    return ret

def search_between(text='', ins='{', outs='}'):
    '''
    returns a list of 2-tuple for each top level part of the text in-bewteen 
    ins and outs expression
    '''
    if len(ins) != len(outs):
        raise(Exception('requires identical length ins and outs'))
    #
    ret = []
    #
    count = {ins:0, outs:0}
    is_top_lvl = lambda c: c[ins] == c[outs]
    entered = False
    #
    for cur in range(len(text)):
        if not entered and text[cur:cur+len(ins)] == ins:
            # passing initial ins char
            entered = True
            start = cur
        if text[cur:cur+len(ins)] in count:
            # counting ins / outs chars
            count[text[cur:cur+len(ins)]] += 1
        if entered and is_top_lvl(count):
            # passing last outs char
            stop = cur + len(ins)
            ret.append( (start, stop) )
            entered = False
    return ret

def extract_curlybrack(text=''):
    '''
    extracts the part of text between "{" and "}" if the "{" is at the start
    of the string
    returns the remaining text, and the extracted content or None
    '''
    text = text.strip()
    offsets = search_between(text, '{', '}')
    if not offsets:
        return text, None
    offsets = offsets[0]
    if offsets[0] != 0:
        return text, None
    return text[offsets[1]:].strip(), text[1:offsets[1]-1].strip()

def extract_parenth(text=''):
    '''
    extracts the part of text between "(" and ")" if the "(" is at the start
    of the string
    returns the remaining text, and the extracted content or None
    '''
    text = text.strip()
    offsets = search_between(text, '(', ')')
    if not offsets:
        return text, None
    offsets = offsets[0]
    if offsets[0] != 0:
        return text, None
    return text[offsets[1]:].strip(), text[1:offsets[1]-1].strip()

def extract_brack(text=''):
    '''
    extracts the part of text between "[" and "]" if the "[" is at the start
    of the string
    returns the remaining text, and the extracted content or None
    '''
    text = text.strip()
    offsets = search_between(text, '[', ']')
    if not offsets:
        return text, None
    offsets = offsets[0]
    if offsets[0] != 0:
        return text, None
    return text[offsets[1]:].strip(), text[1:offsets[1]-1].strip()

def extract_doublebrack(text=''):
    '''
    extracts the part of text between "[[" and "]]" if the "[[" is at the start
    of the string
    returns the remaining text, and the extracted content or None
    '''
    text = text.strip()
    offsets = search_between(text, '[[', ']]')
    if not offsets:
        return text, None
    offsets = offsets[0]
    if offsets[0] != 0:
        return text, None
    return text[offsets[1]:].strip(), text[2:offsets[1]-2].strip()

def convert_bstr(bstr=''):
    '''
    returns a 2-tuple (unsigned integral value, bit length) from a bstring,
    e.g. convert_bstr("'0011010'B") -> (26, 7)
    '''
    return (int(bstr[1:-2], 2), len(bstr[1:-2]))

def convert_hstr(hstr=''):
    '''
    returns a 2-tuple (unsigned integral value, bit length) from a hstring,
    e.g. convert_hstr("'0ABCD1234'H") -> (2882343476, 32)
    '''
    return (int(hstr[1:-2], 16), len(hstr[1:-2])*4)

def flatten(l=[]):
    '''
    returns a list of str from a list of nested str or list,
    in a recursive fashion
    '''
    r = []
    for e in l:
        if isinstance(e, str):
            r.append(e)
        elif isinstance(e, (list, tuple)):
            r.extend(flatten(e))
    return r

def nest(l=[], val=0):
    '''
    returns a nested 2-tuple of all elements from the list l, 
    ultimately associated with val 
    '''
    if len(l) == 1:
        return (l[0], val)
    else:
        return nest(l[:-1], (l[-1], val))

#------------------------------------------------------------------------------#
# integral value processing routines
#------------------------------------------------------------------------------#

def len_bits(val):
    return len(bin(val)[2:])

def len_nibbles(val):
    return len(hex(val)[2:].replace('L', ''))

def len_bytes(val):
    return int(round( len(hex(val)[2:].replace('L', ''))/2.0 ))
#
#