
# Usage

1. Download v2tj.py file
```python
from v2tj import convert_uri_json

uri = "vless://..."
file = convert_uri_json(host="127.0.0.1", port=4142, socksport=4143, uri=uri)

# or file = convert_uri_json("127.0.0.1", 4142, 4143, uri)

# or file = convert_uri_json(uri=uri)

# File saved at /configs
```
# Supported Porotocls

- VLESS+TCP
- VLESS+TCP+HTTP
- VLESS+TCP+TLS
- VLESS+TCP+TLS+HTTP
- VLESS+TCP+REALITY
- VLESS+GRPC+REALITY
- VMESS+TCP
- VMESS+TCP+HTTP
- VMESS+TCP+TLS
- VMESS+TCP+TLS+HTTP
- TROJAN+TCP
- TROJAN+TCP+HTTP
- TROJAN+TCP+TLS
- TROJAN+TCP+TLS+HTTP
- TROJAN+TCP+REALITY
- TROJAN+GRPC+REALITY


