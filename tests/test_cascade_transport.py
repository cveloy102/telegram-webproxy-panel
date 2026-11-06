import base64,json,pathlib,sys,tempfile,types,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'panel'))
import cascade_network as n

def config():
    p={'HeaderProtectionKey':base64.b64encode(b'k'*32).decode(),**{'S'+str(i):32 for i in range(1,5)},**{'H'+str(i):i for i in range(1,5)},'RandomTrailers':'on','ContentPaddingAddition':'0-32'}
    return {'schema':1,'type':'amneziawg-3.1','parameters':p}

class TransportTests(unittest.TestCase):
    def test_legacy_and_optional_transport_are_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)
            self.assertEqual(n.tunnel_tool(root),'wg')
            (root/'transport.json').write_text(json.dumps(config()))
            self.assertEqual(n.tunnel_tool(root),'/usr/local/bin/awg')

    def test_invalid_transport_is_rejected_instead_of_falling_back(self):
        for key,value in [('HeaderProtectionKey','bad'),('S1',4),('S2',64),('ContentPaddingAddition','1\nPostUp=evil'),('RekeyTimeout','7-4'),('RandomTrailers','yes'),('PostUp','evil')]:
            with self.subTest(key=key):
                c=config();c['parameters'][key]=value
                with self.assertRaises(ValueError):n.validate_transport(c)
        c=config();c['type']='unknown'
        with self.assertRaises(ValueError):n.validate_transport(c)

    def test_reapply_keeps_peer_in_syncconf_and_secrets_out_of_argv(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);c=config();private=base64.b64encode(b'p'*32).decode();peer=base64.b64encode(b'e'*32).decode()
            (root/'private.key').write_text(private);(root/'transport.json').write_text(json.dumps(c))
            calls=[];snapshots=[];original=tempfile.NamedTemporaryFile
            def temporary(**kw):kw['dir']=d;return original(**kw)
            def run(*args,**kw):
                calls.append(args)
                if args[1]=='syncconf':snapshots.append(pathlib.Path(args[3]).read_text())
                return types.SimpleNamespace(stdout=peer if args[1]=='show' else '')
            with patch.object(n,'run',side_effect=run),patch.object(n.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)),patch('tempfile.NamedTemporaryFile',side_effect=temporary):
                n.setup_interface(root/'private.key',peer,host='138.16.143.97')
            self.assertIn('PublicKey = '+peer,snapshots[0]);self.assertIn('AllowedIPs = 0.0.0.0/0',snapshots[0])
            self.assertNotIn(private,repr(calls));self.assertNotIn(c['parameters']['HeaderProtectionKey'],repr(calls))
            self.assertFalse(any(p.name.startswith('transport-') for p in root.iterdir()))

if __name__=='__main__':unittest.main()
