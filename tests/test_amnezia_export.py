import base64
import configparser
import json
from pathlib import Path
import struct
import sys
import unittest
import zlib

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'panel'))
from amnezia_export import vpn_key

CONF='''[Interface]
PrivateKey = client-private-synthetic=
Address = 10.77.0.2/32, fd77:77::2/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 100
S1 = 32
S2 = 33
S3 = 34
S4 = 35
H1 = 256
H2 = 257
H3 = 258
H4 = 259
HeaderProtectionKey = synthetic-header-key=

[Peer]
PublicKey = server-public-synthetic=
PresharedKey = psk-synthetic=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
'''


def decode(key):
    packed=base64.urlsafe_b64decode(key[6:]+'='*(-len(key[6:])%4))
    raw=zlib.decompress(packed[4:])
    assert len(raw)==struct.unpack('>I',packed[:4])[0]
    return json.loads(raw)


class AmneziaExportTests(unittest.TestCase):
    def test_connection_only_payload_preserves_all_tunnel_parameters(self):
        key=vpn_key(CONF,'Друг <телефон>')
        self.assertTrue(key.startswith('vpn://'))
        self.assertNotIn('=',key)
        profile=decode(key)
        self.assertEqual(profile['description'],'Друг <телефон>')
        self.assertEqual(profile['defaultContainer'],'amnezia-awg')
        container=profile['containers'][0]
        self.assertEqual(container['container'],'amnezia-awg')
        self.assertTrue(container['awg']['isThirdPartyConfig'])
        client=json.loads(container['awg']['last_config'])
        self.assertEqual(client['config'],CONF)
        self.assertEqual(client['hostName'],'vpn.example.com')
        self.assertEqual(client['port'],51820)
        self.assertEqual(client['client_ip'],'10.77.0.2/32, fd77:77::2/128')
        self.assertEqual(client['allowed_ips'],['0.0.0.0/0','::/0'])
        self.assertEqual(client['mtu'],'1280')
        self.assertEqual(client['persistent_keep_alive'],'25')
        self.assertEqual((profile['dns1'],profile['dns2']),('1.1.1.1','1.0.0.1'))
        native=configparser.ConfigParser();native.optionxform=str;native.read_string(CONF)
        for field in ('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4','HeaderProtectionKey'):
            self.assertEqual(client[field],native['Interface'][field])
        self.assertEqual(client['client_priv_key'],native['Interface']['PrivateKey'])
        self.assertEqual(client['psk_key'],native['Peer']['PresharedKey'])
        self.assertEqual(client['server_pub_key'],native['Peer']['PublicKey'])
        for field in ('userName','password','private_key','api_key'):
            self.assertNotIn(field,profile)


if __name__=='__main__':unittest.main()
