

## ddata

Intended to store a bunch of data/network related utilities that are common for web and big data stuff.

Supported stuff so far:

* jwt
  * rsa256 encoding
  * hs256 encoding
* crytpo
  * aes128 encryption/decryption

That's all for now folks.


## Testing posix version on osx

A dockerfile is provided to be able to run tests un a posix environment if developing on osx:

```
docker build .
```

If that passes then you're good