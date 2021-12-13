# -*- coding: utf-8 -*
from core import search

rule = '''
rule rule1
{
    strings:
        $var = "KNAPSACK"       
    
    condition:
       all of them
}
'''

search.traverse(rule, "C:\\Users\\tr\\Desktop\\study\\")
#search.regex_search("중국인의.*나머지 정리", "C:\\Users\\tr\\Desktop\\study\\", path_regex=".*\.(docx)$")
