"""Connection-only AmneziaVPN export, matching the client's AWG import schema.

No database writes or server credentials; the existing native config remains intact.
"""
import base64
import configparser
import json
import struct
import zlib


def vpn_key(conf, name):
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(conf)
    interface, peer = parser['Interface'], parser['Peer']
    host, port = peer['Endpoint'].rsplit(':', 1)
    client = {
        'config': conf, 'hostName': host.strip('[]'), 'port': int(port),
        'client_priv_key': interface['PrivateKey'], 'client_ip': interface['Address'],
        'server_pub_key': peer['PublicKey'], 'psk_key': peer.get('PresharedKey', ''),
        'mtu': interface['MTU'], 'persistent_keep_alive': peer['PersistentKeepalive'],
        'allowed_ips': [v.strip() for v in peer['AllowedIPs'].split(',')],
    }
    fields = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
              'I1', 'I2', 'I3', 'I4', 'I5', 'HeaderProtectionKey', 'ContentPaddingAddition',
              'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
              'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies')
    client.update({k: interface[k] for k in fields if k in interface})
    dns = [v.strip() for v in interface['DNS'].split(',')]
    profile = {
        'containers': [{'container': 'amnezia-awg', 'awg': {
            'last_config': json.dumps(client, ensure_ascii=False, separators=(',', ':')),
            'isThirdPartyConfig': True, 'port': port, 'transport_proto': 'udp',
        }}],
        'defaultContainer': 'amnezia-awg', 'description': name,
        'hostName': client['hostName'], 'dns1': dns[0], 'dns2': dns[1] if len(dns) > 1 else dns[0],
    }
    raw = json.dumps(profile, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    # Qt qCompress: uncompressed length (big endian uint32), then a zlib stream.
    packed = struct.pack('>I', len(raw)) + zlib.compress(raw, 8)
    return 'vpn://' + base64.urlsafe_b64encode(packed).decode('ascii').rstrip('=')
