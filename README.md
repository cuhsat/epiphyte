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

thread = Epiphyte(b"test")
thread.append(b"Hello World!")

for message in thread:
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
All keys are 40 bytes long and are derived via scrypt (N=16384, p=1) using the
fix salt `epiphyte`. The first 32 bytes of the hash will be used as key and
the last 8 bytes will be used as nonce.

Encryption
----------
Encryption of a new frame is done in the following steps:

1. Generate secure 20 random bytes for the new link.
2. Derive the key and nonce with scrypt from the last plain text data.
3. Encrypt the combined link and data with ChaCha20 using the key and nonce.

Decryption
----------
Decryption of the received frame is done in the following steps:

1. Derive the key and nonce with scrypt from the last plain text data.
2. Decrypt the frame with ChaCha20 using the key and nonce.

Security Considerations
-----------------------
The thread name MUST BE kept secret.

License
=======
Licensed under the terms of the [MIT License](LICENSE).
