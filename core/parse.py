import ply.lex as lex
import ply.yacc as yacc

##################
# referred : https://github.com/8u1a/plyara/blob/master/plyara/interp.py
##################

ERROR_NOT_SUPPORT = "%s is not supported"


class ElementTypes:
    '''An enumeration of the element types emitted by the parser to the interpreter.'''
    RULE_NAME = 1
    METADATA_KEY_VALUE = 2
    STRINGS_KEY_VALUE = 3
    STRINGS_MODIFIER = 4
    IMPORT = 5
    SCOPE = 6
    TAG = 7
    INCLUDE = 8
    CONDITION = 9
    TERM = 10
    UNARY = 11
    BINARY = 12


class token_node:
    def __init__(self, type, operator, operand1, operand2):
        self.type = type
        if type == ElementTypes.TERM:
            self.termname = operator
        else:
            self.operator = operator
        self.operand1 = operand1
        self.operand2 = operand2


class ParserInterpreter:
    '''Interpret the output of the parser and produce an alternative representation of Yara rules.'''

    currentRule = {}
    stringModifiersAccumulator = []
    isPrintDebug = False

    def reset(self, isPrintDebug=False):

        self.currentRule = {}

        self.stringModifiersAccumulator = []
        self.isPrintDebug = isPrintDebug

    def addElement(self, elementType, elementValue):
        '''Accepts elements from the parser and uses them to construct a representation of the Yara rule.'''

        if elementType == ElementTypes.RULE_NAME:
            self.currentRule["rule_name"] = elementValue
            if self.isPrintDebug:
                print("--Adding Rule " + self.currentRule['rule_name'])


        elif elementType == ElementTypes.CONDITION:
            self.currentRule["CONDITION"] = elementValue

        elif elementType == ElementTypes.METADATA_KEY_VALUE:
            if "metadata" not in self.currentRule:
                self.currentRule["metadata"] = {elementValue[0]: elementValue[1]}
            else:
                if elementValue[0] not in self.currentRule["metadata"]:
                    self.currentRule["metadata"][elementValue[0]] = elementValue[1]
                else:
                    if isinstance(self.currentRule["metadata"][elementValue[0]], list):
                        self.currentRule["metadata"][elementValue[0]].append(elementValue[1])
                    else:
                        self.currentRule["metadata"][elementValue[0]] = [self.currentRule["metadata"][elementValue[0]],
                                                                         elementValue[1]]

        elif elementType == ElementTypes.STRINGS_KEY_VALUE:
            # todo
            string_dict = {'name': elementValue[0], 'value': elementValue[1].lower()}

            if len(self.stringModifiersAccumulator) > 0:
                string_dict["modifiers"] = self.stringModifiersAccumulator
                self.stringModifiersAccumulator = []

            if "strings" not in self.currentRule:
                self.currentRule["strings"] = [string_dict]
            else:
                self.currentRule["strings"].append(string_dict)

        elif elementType == ElementTypes.STRINGS_MODIFIER:
            self.stringModifiersAccumulator.append(elementValue)
        else:
            raise Exception('addElement end')

    def buildNode(self, type, operator=None, node1=None, node2=None):
        return token_node(type, operator, node1, node2)

    def printDebugMessage(self, message):
        '''Prints a debug message emitted by the parser if self.isPrintDebug is True.'''
        if self.isPrintDebug:
            print(message)
        return True


# Create an instance of this interpreter for use by the parsing functions.
parserInterpreter = ParserInterpreter()


def parseString(inputString, isPrintDebug=False):
    '''This method takes a string input expected to consist of Yara rules,
    and returns a list of dictionaries that represent them.'''

    if isPrintDebug:
        parserInterpreter.isPrintDebug = True

    parserInterpreter.reset(isPrintDebug=isPrintDebug)

    # Run the PLY parser, which emits messages to parserInterpreter.
    parser.parse(inputString)

    return parserInterpreter.currentRule


########################################################################################################################
# LEXER
########################################################################################################################
tokens = [
    'BYTESTRING',
    'STRING',
    'REXSTRING',
    'EQUALS',
    'STRINGNAME',
    'STRINGNAME_ARRAY',
    'LPAREN',
    'RPAREN',
    'LBRACK',
    'RBRACK',
    'LBRACE',
    'RBRACE',
    'ID',
    'BACKSLASH',
    'FORWARDSLASH',
    'PIPE',
    'PLUS',
    'MINUS',
    'MULT',
    'DIV',
    'MOD',
    'SECTIONMETA',
    'SECTIONSTRINGS',
    'SECTIONCONDITION',
    'COMMA',
    'STRINGCOUNT',
    'GREATERTHAN',
    'LESSTHAN',
    'GREATEREQUAL',
    'LESSEQUAL',
    'PERIOD',
    'COLON',
    'STAR',
    'HYPHEN',
    'AMPERSAND',
    'NEQUALS',
    'EQUIVALENT',
    'DOTDOT',
    'HEXNUM',
    'NUM'
]

reserved = {
    'all': 'ALL',
    'any': 'ANY',
    'of': 'OF',
    'and': 'AND',
    'ascii': 'ASCII',
    'at': 'AT',
    'contains': 'CONTAINS',
    'entrypoint': 'ENTRYPOINT',
    'false': 'FALSE',
    'filesize': 'FILESIZE',
    'for': 'FOR',
    'fullword': 'FULLWORD',
    'global': 'GLOBAL',
    'import': 'IMPORT',
    'in': 'IN',
    'include': 'INCLUDE',
    'int8': 'INT8',
    'int16': 'INT16',
    'int32': 'INT32',
    'int8be': 'INT8BE',
    'int16be': 'INT16BE',
    'int32be': 'INT32BE',
    'matches': 'MATCHES',
    'nocase': 'NOCASE',
    'not': 'NOT',
    'or': 'OR',
    'private': 'PRIVATE',
    'rule': 'RULE',
    'them': 'THEM',
    'true': 'TRUE',
    'wide': 'WIDE',
    'uint8': 'UINT8',
    'uint16': 'UINT16',
    'uint32': 'UINT32',
    'uint8be': 'UINT8BE',
    'uint16be': 'UINT16BE',
    'uint32be': 'UINT32BE',
}

tokens = tokens + list(reserved.values())

# Regular expression rules for simple tokens
t_LPAREN = r'\('
t_RPAREN = r'\)'
t_EQUIVALENT = r'=='
t_NEQUALS = r'!='
t_EQUALS = r'='
t_LBRACE = r'{'
t_RBRACE = r'}'
t_PLUS = r'\+'
t_PIPE = r'\|'
t_BACKSLASH = r'\\'
t_FORWARDSLASH = r'/'
t_COMMA = r','
t_GREATERTHAN = r'>'
t_LESSTHAN = r'<'
t_GREATEREQUAL = r'>='
t_LESSEQUAL = r'<='
t_PERIOD = r'\.'
t_COLON = r':'
t_STAR = r'\*'
t_LBRACK = r'\['
t_RBRACK = r'\]'
t_HYPHEN = r'\-'
t_AMPERSAND = r'&'
t_DOTDOT = r'\.\.'


def t_COMMENT(t):
    r'(//.*)(?=\n)'
    pass
    # No return value. Token discarded


# http://comments.gmane.org/gmane.comp.python.ply/134
def t_MCOMMENT(t):
    # r'/\*(.|\n)*?\*/'
    r'/\*(.|\n|\r|\r\n)*?\*/'
    if '\r\n' in t.value:
        t.lineno += t.value.count('\r\n')
    else:
        t.lineno += t.value.count('\n')
    pass


# Define a rule so we can track line numbers
def t_NEWLINE(t):
    # r'\n+'
    r'(\n|\r|\r\n)+'
    t.lexer.lineno += len(t.value)
    t.value = t.value
    pass


def t_HEXNUM(t):
    r'0x[A-Fa-f0-9]+'
    t.value = t.value
    return t


def t_SECTIONMETA(t):
    r'meta:'
    t.value = t.value
    return t


def t_SECTIONSTRINGS(t):
    r'strings:'
    t.value = t.value
    return t


def t_SECTIONCONDITION(t):
    r'condition:'
    t.value = t.value
    return t


def t_STRING(t):
    # r'".+?"(?<![^\\]\\")'
    r'".*?"(?<![^\\]\\")(?<![^\\][\\]{3}")(?<![^\\][\\]{5}")'
    t.value = t.value
    return t


def t_BYTESTRING(t):
    r'\{[\|\(\)\[\]\-\?a-fA-f0-9\s]+\}'
    t.value = t.value
    return t


def t_REXSTRING(t):
    r'\/.+\/(?=\s|$)'
    t.value = t.value
    return t


def t_STRINGNAME(t):
    r'\$[0-9a-zA-Z\-_*]*'
    t.value = t.value
    return t


def t_STRINGNAME_ARRAY(t):
    r'@[0-9a-zA-Z\-_*]*'
    t.value = t.value
    return t


def t_NUM(t):
    r'\d+(\.\d+)?|0x\d+'
    t.value = t.value
    return t


def t_ID(t):
    r'[a-zA-Z_]{1}[a-zA-Z_0-9.]*'
    t.type = reserved.get(t.value, 'ID')  # Check for reserved words
    return t


def t_STRINGCOUNT(t):
    r'\#[^\s]*'
    t.value = t.value
    return t


# A string containing ignored characters (spaces and tabs)
# t_ignore = ' \t\r\n'
t_ignore = ' \t'


# Error handling rule
def t_error(t):
    raise TypeError("Illegal character " + t.value[0] + " at line " + str(t.lexer.lineno))
    t.lexer.skip(1)


precedence = (('right', 'NUM'), ('right', 'ID'), ('right', 'HEXNUM'))

lexer = lex.lex(debug=False)


########################################################################################################################
# PARSER
########################################################################################################################

def p_rules(p):
    '''rules : rules rule
                     | rule'''


def p_rule(p):
    '''rule : imports_and_scopes RULE ID tag_section LBRACE rule_body RBRACE'''

    parserInterpreter.printDebugMessage('matched rule ' + str(p[3]))
    parserInterpreter.addElement(ElementTypes.RULE_NAME, str(p[3]))


def p_imports_and_scopes(p):
    '''imports_and_scopes : imports
                                                | includes
                                                | scopes
                                                | imports scopes
                                                | includes scopes
                                                | '''


def p_imports(p):
    '''imports : imports import
                         | includes
                         | import'''
    raise Exception(ERROR_NOT_SUPPORT % 'import')


def p_includes(p):
    '''includes : includes include
                            | imports
                            | include'''
    raise Exception(ERROR_NOT_SUPPORT % 'include')


def p_import(p):
    'import : IMPORT STRING'
    # parserInterpreter.printDebugMessage('...matched import ' + p[2])
    # parserInterpreter.addElement(ElementTypes.IMPORT, p[2])

    raise Exception(ERROR_NOT_SUPPORT % 'import')


def p_include(p):
    'include : INCLUDE STRING'
    # parserInterpreter.printDebugMessage('...matched include ' + p[2])
    # parserInterpreter.addElement(ElementTypes.INCLUDE, p[2])

    raise Exception(ERROR_NOT_SUPPORT % 'include')


def p_scopes(p):
    '''scopes : scopes scope
                        | scope'''


def p_tag_section(p):
    '''tag_section : COLON tags
                                 | '''


def p_tags(p):
    '''tags : tags tag
                    | tag'''


def p_tag(p):
    'tag : ID'
    # parserInterpreter.printDebugMessage('matched tag ' + str(p[1]))
    # parserInterpreter.addElement(ElementTypes.TAG, p[1])
    raise Exception(ERROR_NOT_SUPPORT % 'tag')


def p_scope(p):
    '''scope : PRIVATE
                     | GLOBAL'''

    # parserInterpreter.printDebugMessage('matched scope identifier ' + str(p[1]))
    # parserInterpreter.addElement(ElementTypes.SCOPE, p[1])
    raise Exception(ERROR_NOT_SUPPORT % 'scope')


def p_rule_body(p):
    'rule_body : sections'
    parserInterpreter.printDebugMessage('...matched rule body')


def p_rule_sections(p):
    '''sections : sections section
                        | section'''


def p_rule_section(p):
    '''section : meta_section
                         | strings_section
                         | condition_section'''


def p_meta_section(p):
    'meta_section : SECTIONMETA meta_kvs'
    parserInterpreter.printDebugMessage('...matched meta section')


def p_strings_section(p):
    'strings_section : SECTIONSTRINGS strings_kvs'


def p_condition_section(p):
    'condition_section : SECTIONCONDITION expression'
    parserInterpreter.addElement(ElementTypes.CONDITION, p[2])


# Meta elements.

def p_meta_kvs(p):
    '''meta_kvs : meta_kvs meta_kv
                            | meta_kv'''
    parserInterpreter.printDebugMessage('...matched meta kvs')


def p_meta_kv(p):
    '''meta_kv : ID EQUALS STRING
                         | ID EQUALS ID
                         | ID EQUALS TRUE
                         | ID EQUALS FALSE
                         | ID EQUALS NUM'''
    key = str(p[1])
    value = str(p[3])
    parserInterpreter.printDebugMessage('matched meta kv: ' + key + " equals " + value)
    parserInterpreter.addElement(ElementTypes.METADATA_KEY_VALUE, (key, value))


# Strings elements.

def p_strings_kvs(p):
    '''strings_kvs : strings_kvs strings_kv
                                 | strings_kv'''
    parserInterpreter.printDebugMessage('...matched strings kvs')


def p_strings_kv_str(p):
    '''strings_kv : STRINGNAME EQUALS STRING
                                | STRINGNAME EQUALS STRING string_modifiers'''

    key = str(p[1])
    value = str(p[3])

    parserInterpreter.printDebugMessage('matched strings kv: ' + key + " equals " + value)
    parserInterpreter.addElement(ElementTypes.STRINGS_KEY_VALUE, (key[1:], value[1:-1]))


def p_strings_kv_bytestr(p):
    '''strings_kv : STRINGNAME EQUALS BYTESTRING'''
    key = str(p[1])
    value = str(p[3])
    parserInterpreter.printDebugMessage('matched strings kv: ' + key + " equals " + value)
    parserInterpreter.addElement(ElementTypes.STRINGS_KEY_VALUE, (key[1:], value))


def p_strings_kv_rexstr(p):
    '''strings_kv : STRINGNAME EQUALS REXSTRING
                                | STRINGNAME EQUALS REXSTRING string_modifiers'''

    key = str(p[1])
    value = str(p[3])
    parserInterpreter.printDebugMessage('matched strings kv: ' + key + " equals " + value)
    parserInterpreter.addElement(ElementTypes.STRINGS_KEY_VALUE, (key[1:], value))


def p_string_modifers(p):
    '''string_modifiers : string_modifiers string_modifier
                                            | string_modifier'''


def p_string_modifier(p):
    '''string_modifier : NOCASE
                                         | ASCII
                                         | WIDE
                                         | FULLWORD'''
    parserInterpreter.printDebugMessage('...matched a string modifier: ' + p[1])
    parserInterpreter.addElement(ElementTypes.STRINGS_MODIFIER, p[1])


# Condition elements.

def p_expression(p):
    '''expression : logical'''
    p[0] = p[1]


def p_logical(p):
    '''logical : equality
                                | logical AND equality
                                | logical OR equality'''
    if len(p) == 4:
        p[0] = parserInterpreter.buildNode(ElementTypes.BINARY, p[2], p[1], p[3])
    else:
        p[0] = p[1]


def p_equality(p):
    '''equality : relational
                                | equality EQUIVALENT relational
                                | equality NEQUALS relational'''
    if len(p) == 4:
        p[0] = parserInterpreter.buildNode(ElementTypes.BINARY, p[2], p[1], p[3])
    else:
        p[0] = p[1]


def p_relational(p):
    '''relational : addictive
                                | relational GREATERTHAN addictive
                                | relational LESSTHAN addictive
                                | relational GREATEREQUAL addictive
                                | relational LESSEQUAL addictive'''
    if len(p) == 4:
        p[0] = parserInterpreter.buildNode(ElementTypes.BINARY, p[2], p[1], p[3])
    else:
        p[0] = p[1]


def p_addictive(p):
    '''addictive : multiplicative
                                | addictive PLUS multiplicative
                                | addictive MINUS multiplicative'''
    if len(p) == 4:
        p[0] = parserInterpreter.buildNode(ElementTypes.BINARY, p[2], p[1], p[3])
    else:
        p[0] = p[1]


def p_multiplicative(p):
    '''multiplicative : of
                                | multiplicative MULT of
                                | multiplicative DIV of
                                | multiplicative MOD of'''
    if len(p) == 4:
        p[0] = parserInterpreter.buildNode(ElementTypes.BINARY, p[2], p[1], p[3])
    else:
        p[0] = p[1]


def p_of(p):
    '''of : unary
                                | of OF unary'''
    if len(p) == 4:
        p[0] = parserInterpreter.buildNode(ElementTypes.BINARY, p[2], p[1], p[3])
    else:
        p[0] = p[1]


def p_unary(p):
    '''unary : term'''
    # if len(p) == 3:
    #    p[0] = parserInterpreter.buildNode(ElementTypes.UNARY, p[1], p[2])
    # else:
    p[0] = p[1]


def p_termID(p):
    '''term : ID'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'ID', p[1])


def p_termSTRNAME(p):
    '''term : STRINGNAME'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'STRINGNAME', p[1][1:])


def p_termSTRARR(p):
    '''term : STRINGNAME_ARRAY'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'STRINGNAME_ARRAY', p[1])


def p_termTHEM(p):
    '''term : THEM'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'THEM', p[1])


def p_termNUM(p):
    '''term : NUM'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'NUM', int(p[1]))


def p_termTRUE(p):
    '''term : TRUE'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'NUM', 1)


def p_termFALSE(p):
    '''term : FALSE'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'NUM', 0)


def p_termSTRCNT(p):
    '''term : STRINGCOUNT'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'STRINGCOUNT', p[1][1:])


def p_termANY(p):
    '''term : ANY'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'ANY', p[1][1:])


def p_termALL(p):
    '''term : ALL'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'ALL', p[1][1:])


def p_termGROUP(p):
    '''term : LPAREN expression RPAREN'''
    parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
    p[0] = parserInterpreter.buildNode(ElementTypes.TERM, 'GROUP', p[2])


# Error rule for syntax errors
def p_error(p):
    raise TypeError("unknown text at %r ; token of type %r" % (p.value, p.type))


parser = yacc.yacc(debug=False)
