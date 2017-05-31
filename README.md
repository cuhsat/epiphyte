Epiphyte ![Build](https://img.shields.io/travis/cuhsat/epiphyte.svg)
========
The Epiphyte Protocol.

(Ab)using [TinyURL.com](https://tinyurl.com) as a key/value storage for
encrypted, hidden threads.

Usage
-----
```
$ epiphyte.py THREAD [MESSAGE ...]
```

Import
------
```
from epiphyte import Epiphyte

epiphyte = Epiphyte(b"thread")
epiphyte.append(b"message")

for message in epiphyte:
    print(message)
```

Protocol
========
This implementation uses TinyURL.com as a key/value storage. Where the `link`
bytes are encoded in hexadecimal and the `frame` bytes are encoded in URL safe
Base64. The encoded `link` is then used as alias to GET/POST a local dummy URL
with the encoded `frame` as the anchor fragment (`http://127.0.0.1#<frame>`).

**Request**
```
GET /<link> HTTP/1.1
host: tinyurl.com
```

**Request**
```
POST /create.php?url=http%3A%2F%2F127.0.0.1%23<frame>&alias=<link> HTTP/1.1
host: tinyurl.com
```

Structure
---------
A `frame` is build according to the following format:
```
LINK (20 bytes) | DATA (n bytes)
```

A `link` points to the address of next `frame`. If under this address no data
can be found, the end of thread has been reached. For the first link, the
first derived 20 bytes from the threads identifier will be used.

Derivation
----------
All key derivation is done via PKCS#5 v2.0 PBKDF2 (SHA1, 1000 rounds) using
the fix salt `epiphyte`.

Encryption
----------
Encryption of a new frame is done via the following steps:

1. Generate cyptographically secure 20 random bytes as link.
2. Derive the keys bytes with PBKDF2 from the last plain text data.
3. Encrypt the combined link and data with AES-256 in CFB mode
   using the first 16 bytes of the hash as key and the last 16
   bytes as IV.

Decryption
----------
Decryption of the received frame is done via the following steps:

1. Derive the keys bytes with PBKDF2 from the last plain text data.
2. Decrypt the frame with AES-256 CFB in mode using the 16 bytes
   of the hash as key and the last 16 bytes as IV.

Security Considerations
-----------------------
The thread identifier MUST BE kept secret.

License
=======
Licensed under the terms of the [MIT License](LICENSE).
