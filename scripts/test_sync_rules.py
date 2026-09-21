import unittest
from unittest.mock import patch
import sync_rules as s
class SyncTests(unittest.TestCase):
    def test_protected_and_custom(self):
        m={'providers':[{'name':'added','source':'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIp.list','behavior':'classical','protected':True,'output':'rules/managed/001.list'}, {'name':'other','source':'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIp.list','behavior':'classical','protected':False,'output':'rules/managed/002.list'}], 'rules':['RULE-SET,added,DIRECT','RULE-SET,other,DIRECT']}
        text='DOMAIN-SUFFIX,example.org\nDOMAIN-SUFFIX,example.org\n'
        result=s.build(m,{'added':(text,text.splitlines()),'other':(text+'DOMAIN,unique.org\n',text.splitlines()+['DOMAIN,unique.org'])})
        self.assertEqual(result['rules/managed/001.list'],text)
        self.assertEqual(result['rules/managed/002.list'],'DOMAIN,unique.org\n')
        self.assertFalse(any(x.endswith('sercet.list') for x in result))
    def test_different_targets_preserved(self):
        m={'providers':[{'name':n,'source':'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIp.list','behavior':'classical','protected':False,'output':'rules/managed/'+n+'.list'} for n in ('a','b')],'rules':['RULE-SET,a,DIRECT','RULE-SET,b,Proxy']}
        line='DOMAIN,a.example';result=s.build(m,{n:(line,[line]) for n in ('a','b')})
        self.assertEqual(result['rules/managed/a.list'],result['rules/managed/b.list'])
    def test_fetch_failure_prevents_write(self):
        with patch.object(s,'fetch',side_effect=RuntimeError('failed')), patch.object(s.pathlib.Path,'write_text') as write:
            with self.assertRaises(RuntimeError):s.main()
            write.assert_not_called()
    def test_custom_repo_and_tokens_disallowed(self):
        for url in ('https://raw.githubusercontent.com/X1-1U/ME/main/sercet.list','https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIp.list?token=abc'):
            with self.assertRaises(ValueError):s.validate_url(url)
if __name__=='__main__':unittest.main()
