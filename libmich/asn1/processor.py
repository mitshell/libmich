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
# * File Name : asn1/processor.py
# * Created : 2014-10-07
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

import os
try:
    import cPickle as pickle
except ImportError:
    import pickle
#
from utils import *
from parsers import *
import ASN1
#
# only here for commodity, should be removed
from libmich.utils.repr import *
from PER import PER
#ASN1.ASN1Obj.CODEC = PER

PICKLE_PROTOCOL = 2

MODULE_NAMES = [\
    ('rrc3g_25331-c10.asn', 'rrc3g'),
    ('rrclte_36331-c10.asn', 'rrclte'),
    ('ranap_25413-c10.asn', 'ranap'),
    ('s1ap_36413-c10.asn', 's1ap'),
    ('x2ap_36423-c10.asn', 'x2ap')
    ]

def compile(texts, create_pickle_name=''):
    '''
    Scans the texts (or list of texts) to find ASN.1 modules, and compile them
    into Python objects.
    Returns the list of modules, after scanned by scan_modules()
    
    For each module scanned, possibly creates a Python pickled file 
    in MODULES_DIR for further quicker loading of this module within Python
    '''
    # 1) parse subtype definition / content
    if isinstance(texts, str):
        M = process_modules(texts)
    elif isinstance(texts, (tuple, list)):
        M = []
        for t in texts:
            M.extend( process_modules(t) )
    #
    if create_pickle_name:
        path = '%s%s.pck' % (get_modules_dir(), create_pickle_name)
        try:
            fd = open(path, 'wb')
        except:
            raise(ASN1_PROC('Invalid file path for writing module: %s'\
                  % path))
        # create a list of objects according to the compilation order
        obj_list = []
        for mod in M:
            for name in mod['obj']:
                if name in mod['TYPE']:
                    obj_list.append( (name, mod['TYPE'][name]) )
                elif name in mod['VALUE']:
                    obj_list.append( (name, mod['VALUE'][name]) )
                elif name in mod['SET']:
                    obj_list.append( (name, mod['SET'][name]) )
        # pickle all of them within a file
        p = pickle.Pickler(fd, PICKLE_PROTOCOL)
        try:
            p.dump(obj_list)
        except AssertionError:
            log('compiled results storage error: pickle AssertionError')
            log('returning full ASN.1 objects\' list')
            return obj_list
    #
    return M

def load_module(name=''):
    '''
    returns the list of modules compiled and pickled by compile()
    '''
    path = '%s%s.pck' % (get_modules_dir(), os.path.basename(name))
    if not os.path.exists(path):
        raise(ASN1_PROC('invalid module name: %s' % name))
    fd = open(path, 'rb')
    p = pickle.Unpickler(fd)
    try:
        obj_list = p.load()
    except:
        raise(ASN1_PROC('Invalid module content'))
    GLOBAL.clear()
    for obj_name, obj in obj_list:
        if obj['mode'] == 0:
            GLOBAL.TYPE[obj_name] = obj
        elif obj['mode'] == 1:
            GLOBAL.VALUE[obj_name] = obj
        elif obj['mode'] == 2:
            GLOBAL.SET[obj_name] = obj
    log('%s: %s objects loaded into GLOBAL' % (name, len(obj_list)))

def generate_modules(mods=MODULE_NAMES):
    for asn_name, mod_name in mods:
        asn = '%s%s' % (get_asn_dir(), os.path.basename(asn_name))
        fd = open(asn, 'r')
        asntext = fd.read()
        fd.close()
        GLOBAL.clear()
        log('processing %s' % asn_name)
        compile(asntext, mod_name)

def inline(text=''):
    '''
    compile the 1st ASN.1 assignment found in text
    returns the corresponding ASN1Obj
    '''
    text = clean_text(text)
    lines = text.split('\n')
    Obj, rest = get_single_assignment(lines)
    if Obj is not None:
        GLOBAL.clear_tmp()
        init_assignment(Obj)
        process_assignment(Obj)
    return Obj

def get_modules_dir():
    import libmich.asn1 as _asn1
    path = os.path.dirname(_asn1.__file__) + os.path.sep + 'modules' + os.path.sep
    return path

def get_asn_dir():
    import libmich.asn1 as _asn1
    path = os.path.dirname(_asn1.__file__) + os.path.sep + 'asn' + os.path.sep
    return path

#------------------------------------------------------------------------------#
# module processor
#------------------------------------------------------------------------------#
# 1) identify a DEFINITIONS indicating a module
# module-name DEFINITIONS [TAGS processing] ::=
# IMPORT ...
# EXPORT ...
# BEGIN
# [ASN.1 code]
# END
# -> module-name
# -> tags processing options
# -> imports
# -> export
#
# 2) identify all assignment within the ASN.1 BEGIN-END block
# -> 1-line all definitions, remove all blank spaces / CR / comments
# -> tokenize and parse all definitions into ASN1Obj object

def process_modules(text=''):
    '''
    Scans ASN.1 text definition file for module definition
    
    Returns a list of dict, each dict corresponding to an ASN.1 module.
    Each dict has the following keys:
        - name: str, module name
        - oid: str or None
        - tags: str (EXPLICIT, IMPLICIT, AUTOMATIC)
        - ext: type str (IMPLIED) or None
        - export: list or None
        - import: list or None
          The import list contains dict,
          each of which has the following keys:
            - name: str
            - oid: str or None
            - obj: list of str
        - assign: OrderedDict or None
          The assign dict is indexed by user-defined ASN.1 names
          and references ASN1Obj as set by get_single_assign()
        - obj: list
          The obj list lists all ASN.1 object in the order they have been
          compiled         
    '''
    text = clean_text(text)
    modules = []
    #
    # scan the text for all ASN.1 modules defined
    while True:
        module = {}
        #
        # 1) scan text for module DEFINITION
        m = re.search('\s{1,}(DEFINITIONS)\s{1,}', text)
        if not m:
            break
        name, oid = get_module_name(text[:m.start()])
        module['name'] = name
        if oid:
            module['oid'] = oid
            parse_value_oid(module, '{%s}' % oid)
            # this sets a proper list of uint in module['val']
        else:
            module['oid'] = None
        text = text[m.end():]
        #
        # 2) scan text for module option
        m = re.search('::=', text)
        if not m:
            raise(ASN1_PROC_TEXT('module %s definition: no initial "::="' % name))
        tag, ext = get_module_option(text[:m.start()])
        module['tags'] = tag
        module['extensibility'] = ext
        MODULE_OPT.TAG = module['tags']
        MODULE_OPT.EXT = module['extensibility']
        text = text[m.end():]
        #
        # 3) scan text for BEGIN - END block
        m = re.search('BEGIN((.|\n)*?)END', text)
        if not m:
            raise(ASN1_PROC_TEXT('module %s definition: no BEGIN - END' % name))
        block = m.group(1)
        text = text[m.end():]
        #
        # 4) scan block for module exports
        module['export'], cur = get_module_export(block)
        if cur:
            block = block[cur:]
        #
        # 5) scan block for module imports
        module['import'], cur = get_module_import(block)
        if cur:
            block = block[cur:]
        #
        # 6) scan block for assignments and process them
        module['assign'] = get_module_assign(block)
        obj_nums, module['obj'] = process_module_content( module )
        #
        # 7) reorder assignments processed into TYPE, VALUE, SET dicts
        module['TYPE'] = OD()
        module['VALUE'] = OD()
        module['SET'] = OD()
        for name in module['obj']:
            obj = module['assign'][name]
            if   obj['mode'] == 0: module['TYPE'][name] = obj
            elif obj['mode'] == 1: module['VALUE'][name] = obj
            elif obj['mode'] == 2: module['SET'][name] = obj
        del module['assign']
        #
        modules.append(module)
        log('[proc] ASN.1 module %s: %i assignments processed (%i pass)'\
            % (module['name'], len(module['obj']), len(obj_nums)))
    #
    assign_num = sum([len(m['obj']) for m in modules])
    log('[proc] ASN.1 modules scanned: %s' % [m['name'] for m in modules])
    return modules

def get_module_name(text=''):
    # check for the module name
    name_all = SYNT_RE_MODULEREF.findall(text)
    if not name_all:
        raise(ASN1_PROC_TEXT('no module name found'))
    name, oid = name_all[-1]
    # clean-up the oid
    if oid:
        oid = re.sub('\s{1,}', ' ', oid[1:-1]).strip()
    else:
        oid = None
    return name, oid

def get_module_option(text=''):
    text = ' %s' % text
    # check for tagging
    m = re.search('(?:^|\s{1})(EXPLICIT\s{1,}TAGS|IMPLICIT\s{1,}TAGS|AUTOMATIC\s{1,}TAGS)', text)
    if m:
        tag = m.group(1).split()[0].strip()
    else:
        # default ASN.1 mode
        tag = TAG_EXPLICIT
    # check for extensivity
    m = re.search('(?:^|\s{1})(EXTENSIBILITY\s{1,}IMPLIED)', text)
    if m:
        ext = m.group(1).split()[1].strip()
    else:
        ext = None
    return tag, ext

def get_module_export(text=''):
    # check for export clause
    m = re.search('(?:^|\s{1})EXPORTS((.|\n)*?);', text)
    if m:
        # remove CR
        exp = m.group(1).replace('\n', ',').strip()
        # remove duplicated spaces / comas
        exp = re.sub('[ ]{0,},{1,}[ ]{0,},{1,}[ ]{0,}', ', ', exp)
        # split, strip, and keep only strings
        exp = [s for s in map(stripper, exp.split(',')) if s != '']
        return exp, m.end()
    else:
        return None, 0

def get_module_import(text=''):
    # check for import clauses (can be from multiple modules)
    m = re.search('(?:^|\s{1})IMPORTS((.|\n)*?);', text)
    if m:
        l = []
        imp = m.group(1)
        if not re.match('\s{0,}', imp):
            # in case of "IMPORTS ;"
            return None, m.end()
        # take care of FROM directives, that can reference complete module name
        fro = SYNT_RE_MODULEFROM.search(imp)
        while fro:
            # get module name / oid
            name, oid = fro.groups()
            # clean-up the oid
            if oid:
                oid = re.sub('\s{1,}', ' ', oid[1:-1]).strip()
            else:
                oid = None
            # get all ASN.1 objects reference before
            obj = imp[:fro.start()]
            # clean them up and split them to a list
            obj = map(stripper, re.sub('\s{1,}', ' ', obj).split(','))
            # remove {} at the end of parameterized object
            obj = [o[:-2] if o[-2:] == '{}' else o for o in obj] 
            # fill-in the import list
            l.append({'name':name, 'oid':oid, 'obj':obj})
            # iterate
            imp = imp[fro.end():]
            fro = SYNT_RE_MODULEFROM.search(imp)
        return l, m.end()
    else:
        return None, 0

def get_module_assign(text=''):
    # in order to not require a full syntactic analysis,
    # we assume the following for object assignment:
    # - assignment sign "::=" and its left part are on a single line
    # - left part of the assignment starts at the beginning of the line
    # ... actually that's all !!! But that is not conforming to ITU-T spec.
    lines = text.split('\n')
    assignments = OD()
    while len(lines) > 0:
        Obj, lines = get_single_assignment(lines)
        init_assignment(Obj)
        assignments[Obj._name] = Obj
    return assignments

def get_single_assignment(lines=[]):
    '''
    Scans the lines until there is a 1st assignment "::=".
    From here, scans the declaration left-part of "::=" on the same line,
    and the definition text of the declared object, right-part of "::=".
    
    It returns an initialized ASN1Obj object with additional keys:
        - text_decl: str, left-part of the assignment, ASN.1 declaration
        - text_def: str, right-part of the assignment, ASN.1 definition
    '''
    content, entered, Obj = [], False, None
    line_num = 0
    #
    for l in lines:
        if l.find('::=') >= 0:
            if not entered:
                # we found a 1st assignment, to parse
                entered = True
                declared, definition = map(stripper, l.split('::='))
                if definition:
                    content.append(definition)
                # parse left part of the assignment
                Obj = ASN1.ASN1Obj()
                Obj._text_decl = declared
            else:
                # we are on a 2nd new assignments, just returning the 1st object
                Obj._text_def = re.sub('\s{1,}', ' ', ' '.join(content).strip())
                lines = lines[line_num:]
                return Obj, lines
        #
        elif entered:
            content.append(l)
        line_num += 1
    #
    # end of lines
    if Obj is not None:
        Obj._text_def = re.sub('\s{1,}', ' ', ' '.join(content).strip())
    lines = []
    return Obj, lines

def init_assignment(Obj):
    '''
    Processes the name and mode (0:type, 1:value, 1:set) of the assignment
    '''
    text = Obj._text_decl
    #
    m0 = SYNT_RE_TYPEREF.match(text)
    if not m0:
        # 1) check for value assignment
        m1 = SYNT_RE_IDENT.match(text)
        if not m1:
            raise(ASN1_PROC_TEXT('invalid syntax for name: %s' % text))
        # get lower-case 1st lexeme
        Obj['name'] = m1.group(1)
        text = text[m1.end():].strip()
        # remove potential formal parameters
        text_rest, text_param = extract_curlybrack(text)
        #
        m2 = SYNT_RE_TYPEREF.match(text_rest)
        if not m2:
            raise(ASN1_PROC_TEXT('%s: invalid syntax for TypeRef: %s'\
                  % (Obj['name'], Obj._text_decl)))
        # upper-case 2nd lexeme -> value assignment
        Obj['mode'] = 1
        Obj._text_decl = text
        return
    #
    # 2) check for type or set assignment
    # upper-case 1st lexeme
    Obj['name'] = m0.group(1)
    text = text[m0.end():].strip()
    # remove potential formal parameters
    text_rest, text_param = extract_curlybrack(text)
    #
    # 3) check for set assignment
    # get potential ASN.1 object type / class
    m1 = SYNT_RE_TYPEREF.match(text_rest)
    if m1:
        # upper-case 2nd lexeme -> set assignment
        Obj['mode'] = 2
        Obj._text_decl = text
        return
    #
    # 4) -> subtype (or class) assignment
    Obj['mode'] = 0
    Obj._text_decl = text

def process_module_content(module):
    '''
    Ensures IMPORT FROM objects are available into GLOBAL scope
    and processes all assignments of the module
    '''
    if module['import'] is not None:
        for mod in module['import']:
            for obj in mod['obj']:
                if obj not in GLOBAL.TYPE \
                and obj not in GLOBAL.VALUE \
                and obj not in GLOBAL.SET:
                    raise(ASN1_PROC_LINK('module %s: missing IMPORT object: %s'\
                          % (module['name'], obj)))
    #
    # if all IMPORT required are available, we should be able to process 
    # all module's assignments
    GLOBAL.clear_tmp()
    for assignment in module['assign']:
        GLOBAL.OBJ.append(module['assign'][assignment])
    #
    # process_each_assignment, as many times as needed,
    # in order to empty GLOBAL.OBJ
    # if GLOBAL.OBJ cannot be empty, this means there are self 
    # or circular references within unprocessed objects
    obj_num = [len(GLOBAL.OBJ)]
    obj_list = []
    while obj_num[-1] > 0:
        for obj in GLOBAL.OBJ:
            name = obj._name
            mode = obj._mode
            try:
                process_assignment(obj)
            except ASN1_PROC_LINK:
                obj.__init__(name=name, mode=mode)
            else:
                GLOBAL.OBJ.remove(obj)
                obj_list.append(name)
        obj_num.append( len(GLOBAL.OBJ) )
        if obj_num[-1] == obj_num[-2]:
            log('unable to process %s objects:' % obj_num[-1])
            for obj in GLOBAL.OBJ:
                log(obj['name'])
            raise(ASN1_PROC_LINK('bad reference... no luck'))
    return obj_num, obj_list

#------------------------------------------------------------------------------#
# assignment processor
#------------------------------------------------------------------------------#
def process_assignment(Obj):
    '''
    Processes the left part of the assignment to populate the ASN1Obj
    with the following information :
    if mode 0
        [- param]
    if mode 1 or 2
        [- param]
        [- tag]
        - type
        [- typeref]
        [- cont]
        [- const]
    
    and the right part of the assignment to populate Obj with the following 
    information:
    if mode 0
        [- tag]
        - type
        [- typeref]
        [- cont]
        [- const]
        [- syntax]
    if mode 1 or 2
        - val
    '''
    # 1) parse potential formal parameter, whatever mode
    text_decl = Obj.parse_param(Obj._text_decl)
    #
    # 2a) process value / set assignment
    if Obj['mode'] in (1, 2):  
        text_decl = Obj.parse_definition(text_decl)
        text_def  = Obj.parse_value(Obj._text_def)
        if Obj['mode'] == 1:
            GLOBAL.VALUE[Obj['name']] = Obj
        elif Obj['mode'] == 2:
            GLOBAL.SET[Obj['name']] = Obj
    #
    # 2b) process type assignment
    elif Obj['mode'] == 0:
        text_def  = Obj.parse_definition(Obj._text_def)
        GLOBAL.TYPE[Obj['name']] = Obj
    #
    # 3) ensures no textual syntax is remaining
    if SYNT_RE_REMAINING.match(text_decl):
        raise(ASN1_PROC_TEXT('%s: remaining declaration syntax: %s'\
              % (Obj['name'], text_decl)))
    elif SYNT_RE_REMAINING.match(text_def):
        raise(ASN1_PROC_TEXT('%s: remaining definition syntax: %s'\
              % (Obj['name'], text_def)))
    