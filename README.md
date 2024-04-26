
# Usage

1. Download v2tj.py file
```python
from v2tj import convert_uri_json

uri = "vless://..."
file = convert_uri_json(uri=uri)

#or Custom address & port:
#file = convert_uri_json(host="127.0.0.1", port=4142, socksport=4143, uri=uri)
# or file = convert_uri_json("127.0.0.1", 4142, 4143, uri)

# File saved at /configs
```
# Supported Porotocls

- VLESS+GRPC
- VLESS+GRPC+TLS
- VLESS+TCP
- VLESS+TCP+HTTP
- VLESS+TCP+TLS
- VLESS+TCP+TLS+HTTP
- VLESS+TCP+REALITY
- VLESS+GRPC+REALITY
- VLESS+WS
- VLESS+WS+TLS
- VLESS+WS+HTTP
- VLESS+WS+HTTP+TLS
- VMESS+GRPC
- VMESS+GRPC+TLS
- VMESS+TCP
- VMESS+TCP+HTTP
- VMESS+TCP+TLS
- VMESS+TCP+TLS+HTTP
- VMESS+WS
- VMESS+WS+TLS
- VMESS+WS+HTTP
- VMESS+WS+HTTP+TLS
- TROJAN+TCP
- TROJAN+TCP+HTTP
- TROJAN+TCP+TLS
- TROJAN+TCP+TLS+HTTP
- TROJAN+TCP+REALITY
- TROJAN+GRPC+REALITY
- TROJAN+GRPC+TLS
- TROJAN+WS
- TROJAN+WS+TLS
- TROJAN+WS+HTTP
- TROJAN+WS+HTTP+TLS
