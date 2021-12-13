from core import parse
from core.Searcher import Searcher


class Yarastr:
    def __init__(self, key, mod, value):
        self.key = key
        self.mod = mod
        self.value = value
        self.count = -1


class ASTTraversal(Searcher):
    def __init__(self, ast, dir_path, path_regex, extensions):
        super().__init__(dir_path, path_regex, extensions)
        root = None
        string_table = []
        if 'CONDITION' in ast:
            root = ast['CONDITION']

        if 'strings' in ast:
            for strr in ast['strings']:
                if 'modifiers' in strr:
                    string_table.append(Yarastr(strr['name'], strr['modifiers'], strr['value']))
                else:
                    string_table.append(Yarastr(strr['name'], 'ascii', strr['value']))

        self.string_table = string_table
        self.ast_root = root

    def execute_one(self):
        self.reset_yara_str()
        root = self.ast_root
        return self.dispatcher(root)

    def dispatcher(self, node):
        if node.type == parse.ElementTypes.TERM:
            return self.d_term(node)
        else:
            op = node.operator
            if op == 'and' or op == 'or':
                return self.d_logical(node)
            elif op == '==' or op == '!=':
                return self.d_equility(node)
            elif op == '>' or op == '<' or op == '>=' or op == '<=':
                return self.d_relational(node)
            elif op == '+' or op == '-':
                return self.d_addictive(node)
            elif op == '*' or op == '/' or op == '%':
                return self.d_multiplicative(node)
            elif op == 'of':
                return self.d_of(node)
        raise Exception('reach end of dispatcher')

    def d_logical(self, node):
        op = node.operator
        if op == 'or':
            return (self.dispatcher(node.operand1)) or (self.dispatcher(node.operand2))
        elif op == 'and':
            return (self.dispatcher(node.operand1)) and (self.dispatcher(node.operand2))
        raise Exception('reach end of d_logical')

    def d_equility(self, node):
        op = node.operator
        if op == '==':
            return self.dispatcher(node.operand1) == self.dispatcher(node.operand2)
        elif op == '!=':
            return self.dispatcher(node.operand1) != self.dispatcher(node.operand2)
        raise Exception('reach end of d_equility')

    def d_relational(self, node):
        op = node.operator
        if op == '>':
            return self.dispatcher(node.operand1) > self.dispatcher(node.operand2)
        elif op == '<':
            return self.dispatcher(node.operand1) < self.dispatcher(node.operand2)
        elif op == '>=':
            return self.dispatcher(node.operand1) >= self.dispatcher(node.operand2)
        elif op == '<=':
            return self.dispatcher(node.operand1) <= self.dispatcher(node.operand2)
        raise Exception('reach end of d_relational')

    def d_addictive(self, node):
        op = node.operator
        if op == '+':
            return self.dispatcher(node.operand1) + self.dispatcher(node.operand2)
        elif op == '-':
            return self.dispatcher(node.operand1) - self.dispatcher(node.operand2)
        raise Exception('reach end of d_addictive')

    def d_multiplicative(self, node):
        op = node.operator
        if op == '*':
            return self.dispatcher(node.operand1) * self.dispatcher(node.operand2)
        elif op == '/':
            return self.dispatcher(node.operand1) / self.dispatcher(node.operand2)
        elif op == '%':
            return self.dispatcher(node.operand1) % self.dispatcher(node.operand2)
        raise Exception('reach end of d_addictive')

    def d_of(self, node):
        opr1 = node.operand1
        if node.operand1.type != parse.ElementTypes.TERM or \
                (
                        node.operand1.termname != 'ANY' and node.operand1.termname != 'ALL' and node.operand1.termname != 'NUM') or \
                (node.operand2.termname != 'THEM'):
            raise Exception('of grammar error ')

        if opr1.termname == 'ANY':
            return self.d_cnt_str_find(1, self.string_table)
        elif opr1.termname == 'ALL':
            return self.d_cnt_str_find(-1, self.string_table)
        elif opr1.termname == 'NUM':
            return self.d_cnt_str_find(opr1.operand1, self.string_table)
        raise Exception('reach end of d_of')

    def d_term(self, node):
        termname = node.termname
        if termname == 'STRINGNAME':
            return self.d_get_str_cnt(node) > 0
        elif termname == 'STRINGCOUNT':
            return self.d_get_str_cnt(node)
        elif termname == 'NUM':
            return node.operand1
        elif termname == 'GROUP':
            return self.dispatcher(node.operand1)
        return 0

    def d_cnt_str_find(self, target_cnt, string_table):
        cur_cnt = 0
        if target_cnt == -1:
            target_cnt = len(string_table)
        for ystr in string_table:
            if ystr.count == -1:
                ystr.count = self.abstract_file.count_string(ystr.value)
            if ystr.count > 0:
                cur_cnt += 1
            if cur_cnt > target_cnt:
                return False
        if cur_cnt == target_cnt:
            return True
        return False

    def d_get_str_cnt(self, node):
        ystr = self.get_ystr_of_key(node.operand1)
        if ystr.count == -1:
            ystr.count = self.abstract_file.count_string(ystr.value)
        return ystr.count

    def get_ystr_of_key(self, key):
        for i in range(0, len(self.string_table)):
            if key == self.string_table[i].key:
                return self.string_table[i]
        raise Exception('string not found:%s' % key)

    def reset_yara_str(self):
        for ystr in self.string_table:
            ystr.count = -1


class RegexSearcher(Searcher):
    def __init__(self, regex, dir_path, path_regex, extensions):
        super().__init__(dir_path, path_regex, extensions)
        self.regex = regex

    def execute_one(self):
        return self.abstract_file.regex_search(self.regex) is not None


def traverse(yara, dirpath, path_regex=None, extentions=None):
    ast = parse.parseString(yara)

    traversal = ASTTraversal(ast, dirpath, path_regex, extentions)
    traversal.execute()


def regex_search(regex, dirpath, path_regex=None, extentions=None):
    searcher = RegexSearcher(regex, dirpath, path_regex, extentions)
    searcher.execute()
