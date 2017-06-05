Epiphyte ![Build](https://img.shields.io/travis/cuhsat/epiphyte.svg)
========
The Epiphyte Protocol.

(Ab)using [TinyURL.com](https://tinyurl.com) as a key/value storage for
hidden and encrypted message threads.

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

TinyURL
-------
This implementation uses TinyURL.com as a key/value storage. Where the `key`
bytes are encoded in hexadecimal and the `value` bytes are encoded in URL safe
Base64. The encoded `key` is then used as alias to POST/GET a local dummy URL
with the encoded `value` as the anchor fragment (`http://127.0.0.1/#<value>`).

POST request:
```
POST /create.php?url=http%3A%2F%2F127.0.0.1%2F%23<value>&alias=<key> HTTP/1.1
host: tinyurl.com
```

GET request:
```
GET /<key> HTTP/1.1
host: tinyurl.com
```

Splitting
---------
All values larger than 4096 bytes will be splitted into different frames. A
`frame` is build according to the following format:
```
[ LINK (20 bytes) | DATA (1 to 4096 bytes) ]
```

The `link` is the key of the next frame. If no value is returned for this
key, the current end of the thread has been reached. The next frame must be
stored under this key. For the first key, the first derived 20 bytes from the
threads hashed name will be used.

Key Derivation
--------------
All encryption keys are 32 bytes long and are derived via PKCS#5 v2.0 PBKDF2
(SHA1, 1000 rounds) using the fix salt `epiphyte`. The first 16 bytes of the
hash will be used as key and the last 16 bytes will be used as initialization
vector.

Encryption
----------
Encryption of a new frame is done in the following steps:

1. Generate secure 20 random bytes for the new link.
2. Derive the key with PBKDF2 from the last plain text data.
3. Encrypt the combined link and data with AES-256 in CFB mode using the key.

Decryption
----------
Decryption of the received frame is done in the following steps:

1. Derive the key with PBKDF2 from the last plain text data.
2. Decrypt the frame with AES-256 in CFB mode using the key.

Security Considerations
-----------------------
The thread name MUST BE kept secret.

License
=======
Licensed under the terms of the [MIT License](LICENSE).