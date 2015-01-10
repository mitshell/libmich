1) How to compile an ASN.1 module ?
Some ASN.1 definition files are available in the asn/ sub-directory,

1.1) this is how to compile them into Python pickle module:
Pickle modules are created in the modules/ sub-directory.
It's possible to call them back for further use, without recompiling from the .asn file.
The compilation of complete ASN.1 textual definition is done with the function compile().

    >>> from libmich.asn1.processor import *
    >>> asndir = get_asn_dir()
    >>> fd = open(asndir + 'ranap_25413-c10.asn'); asn = fd.read(); fd.close()
    >>> M = compile(asn, 'ranap')
    [proc] ASN.1 module RANAP-CommonDataTypes: 7 assignments processed (4 pass)
    [proc] ASN.1 module RANAP-Constants: 353 assignments processed (10 pass)
    [proc] ASN.1 module RANAP-Containers: 14 assignments processed (6 pass)
    [proc] ASN.1 module RANAP-IEs: 488 assignments processed (15 pass)
    [proc] ASN.1 module RANAP-PDU-Contents: 391 assignments processed (13 pass)
    [proc] ASN.1 module RANAP-PDU-Descriptions: 57 assignments processed (14 pass)
    [proc] ASN.1 modules scanned: ['RANAP-CommonDataTypes', 'RANAP-Constants', 'RANAP-Containers', 'RANAP-IEs', 'RANAP-PDU-Contents', 'RANAP-PDU-Descriptions']

    >>> GLOBAL.clear()

    >>> fd = open(asndir + 'rrc3g_25331-c10.asn'); asn = fd.read(); fd.close()
    >>> M = compile(asn, 'rrc3g')
    [proc] ASN.1 module Constant-definitions: 173 assignments processed (9 pass)
    [proc] ASN.1 module InformationElements: 3302 assignments processed (23 pass)
    [proc] ASN.1 module PDU-definitions: 555 assignments processed (12 pass)
    [proc] ASN.1 module Class-definitions: 23 assignments processed (6 pass)
    [proc] ASN.1 module Internode-definitions: 144 assignments processed (14 pass)
    [proc] ASN.1 modules scanned: ['Constant-definitions', 'InformationElements', 'PDU-definitions', 'Class-definitions', 'Internode-definitions']

    >>> GLOBAL.clear()

    >>> fd = open(asndir + 'rrclte_36331-c10.asn'); asn = fd.read(); fd.close()
    >>> M = compile(asn, 'rrclte')
    [proc] ASN.1 module EUTRA-RRC-Definitions: 821 assignments processed (30 pass)
    [proc] ASN.1 module EUTRA-UE-Variables: 15 assignments processed (7 pass)
    [proc] ASN.1 module EUTRA-InterNodeDefinitions: 23 assignments processed (10 pass)
    [proc] ASN.1 modules scanned: ['EUTRA-RRC-Definitions', 'EUTRA-UE-Variables', 'EUTRA-InterNodeDefinitions']

    >>> GLOBAL.clear()

    >>> fd = open(asndir + 's1ap_36413-c10.asn'); asn = fd.read(); fd.close()
    >>> M = compile(asn, 's1ap')
    [proc] ASN.1 module S1AP-CommonDataTypes: 7 assignments processed (4 pass)
    [proc] ASN.1 module S1AP-Constants: 258 assignments processed (10 pass)
    [proc] ASN.1 module S1AP-Containers: 15 assignments processed (6 pass)
    [proc] ASN.1 module S1AP-IEs: 340 assignments processed (15 pass)
    [proc] ASN.1 module S1AP-PDU-Contents: 216 assignments processed (11 pass)
    [proc] ASN.1 module S1AP-PDU-Descriptions: 58 assignments processed (12 pass)
    [proc] ASN.1 modules scanned: ['S1AP-CommonDataTypes', 'S1AP-Constants', 'S1AP-Containers', 'S1AP-IEs', 'S1AP-PDU-Contents', 'S1AP-PDU-Descriptions']

    >>> GLOBAL.clear()

    >>> fd = open(asndir + 'x2ap_36423-c10.asn'); asn = fd.read(); fd.close()
    >>> M = compile(asn, 'x2ap')
    [proc] ASN.1 module X2AP-CommonDataTypes: 9 assignments processed (5 pass)
    [proc] ASN.1 module X2AP-Constants: 136 assignments processed (9 pass)
    [proc] ASN.1 module X2AP-Containers: 15 assignments processed (6 pass)
    [proc] ASN.1 module X2AP-IEs: 245 assignments processed (12 pass)
    [proc] ASN.1 module X2AP-PDU-Contents: 109 assignments processed (12 pass)
    [proc] ASN.1 module X2AP-PDU-Descriptions: 24 assignments processed (11 pass)
    [proc] ASN.1 modules scanned: ['X2AP-CommonDataTypes', 'X2AP-Constants', 'X2AP-Containers', 'X2AP-IEs', 'X2AP-PDU-Contents', 'X2AP-PDU-Descriptions']

    >>> GLOBAL.clear()

    >>> load_module('ranap')
    1310 objects loaded into GLOBAL

    >>> GLOBAL.clear()

    >>> load_module('rrc3g')
    4197 objects loaded into GLOBAL

    >>> GLOBAL.clear()

    >>> load_module('rrclte')
    859 objects loaded into GLOBAL

    >>> GLOBAL.clear()

    >>> load_module('s1ap')
    894 objects loaded into GLOBAL

    >>> GLOBAL.clear()

    >>> load_module('x2ap')
    538 objects loaded into GLOBAL

    >>> GLOBAL.clear()

1.2) it is also possible to compile an ASN.1 definition without creating Python pickle modules.

    >>> M = compile(asn)
    [proc] ASN.1 module X2AP-CommonDataTypes: 9 assignments processed (5 pass)
    [proc] ASN.1 module X2AP-Constants: 136 assignments processed (9 pass)
    [proc] ASN.1 module X2AP-Containers: 15 assignments processed (6 pass)
    [proc] ASN.1 module X2AP-IEs: 245 assignments processed (12 pass)
    [proc] ASN.1 module X2AP-PDU-Contents: 109 assignments processed (12 pass)
    [proc] ASN.1 module X2AP-PDU-Descriptions: 24 assignments processed (11 pass)
    [proc] ASN.1 modules scanned: ['X2AP-CommonDataTypes', 'X2AP-Constants', 'X2AP-Containers', 'X2AP-IEs', 'X2AP-PDU-Contents', 'X2AP-PDU-Descriptions']

1.3) it is possible to compile inlined ASN.1 definition within the Python interpreter.
This is done with the function inline().

    >>> Test = inline('Test ::= INTEGER (0..2500, ...)')
    >>> test = inline('test Test ::= 1200')
    >>> Test
    <Test (INTEGER type)>
    >>> test
    <test (INTEGER value): 1200>

2) How to use compiled Python objects ?
When compiling an ASN.1 textual definition, Python objects are all created in a common container called GLOBAL.
GLOBAL has 3 attributes:
- TYPE, which lists all ASN.1 user-defined types
- VALUE, which lists all ASN.1 static values
- SET, which lists all ASN.1 static sets
GLOBAL has a clear() method too, in order to reset those 3 attributes.

    >>> load_module('s1ap')
    894 objects loaded into GLOBAL
    >>> GLOBAL.TYPE
    Criticality: <Criticality (ENUMERATED type)>
    PrivateIE-ID: <PrivateIE-ID (CHOICE type)>
    ProtocolExtensionID: <ProtocolExtensionID (INTEGER type)>
    TriggeringMessage: <TriggeringMessage (ENUMERATED type)>
    Presence: <Presence (ENUMERATED type)>
    ProtocolIE-ID: <ProtocolIE-ID (INTEGER type)>
    ProcedureCode: <ProcedureCode (INTEGER type)>
    S1AP-PROTOCOL-IES: <S1AP-PROTOCOL-IES (CLASS type)>
    [...]
    E-RABModifyResponse: <E-RABModifyResponse (SEQUENCE type)>
    UEContextReleaseRequest: <UEContextReleaseRequest (SEQUENCE type)>
    PathSwitchRequestFailure: <PathSwitchRequestFailure (SEQUENCE type)>
    MMEConfigurationTransfer: <MMEConfigurationTransfer (SEQUENCE type)>
    InitialContextSetupRequest: <InitialContextSetupRequest (SEQUENCE type)>
    S1AP-ELEMENTARY-PROCEDURE: <S1AP-ELEMENTARY-PROCEDURE (CLASS type)>
    InitiatingMessage: <InitiatingMessage (SEQUENCE type)>
    UnsuccessfulOutcome: <UnsuccessfulOutcome (SEQUENCE type)>
    SuccessfulOutcome: <SuccessfulOutcome (SEQUENCE type)>
    S1AP-PDU: <S1AP-PDU (CHOICE type)>

2.1) Each user-defined ASN.1 type have those common methods:
- set_val(val), which sets a value in the _val attribute to the given type
- encode(), which encodes the value set into a structure, according to the CODEC attribute;
the generated structure is built into the _msg attribute, and the buffer can be obtained
by using the Python built-in __str__() method on the ASN1 object
- decode(string), which decodes a string into a structure in the _msg attribute 
and set the proper value in the _val attribute, according to the CODEC attribute 

After encode()ing or decode()ing an ASN.1 object, the structured message is available in the _msg attribute.
The show() method allow for nice printing of the structured message.

2.2) A value can be taken from GLOBAL.VALUE, or be obtained after setting a value with .set_val(val) to a user-defined ASN.1 type.
It is called with the Python built-in __call__() method.

2.3) All Python objects generated have a CODEC attribute which must point to a valid encoder / decoder.
A CODEC must be a class which has a _name attribute, and encode() / decode() methods.
At this time, only a PER aligned / unaligned codec is provided.

3) The ASN1Obj object, defined in the ASN1.py file has a full explanatory docstring.
For further manipulation, please read the Python code in the test.py file, which implements 
a lot of testing.
