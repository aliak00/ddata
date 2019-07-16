module ddata.crypto.decrypt;

import std.format: format;
import std.conv: to;

import deimos.openssl.evp;

import ddata.common;
import ddata.crypto.algorithm;

/**
    Decrypts the data using a key with the specified algorithm

    See_Also:
        `ddata.crypto.encrypt`
*/
public string decrypt(string data, string key, Algorithm algorithm = Algorithm.aes128) @safe {
    final switch (algorithm) {
    case Algorithm.aes128:
        return decrypt(cast(ubyte[])data.dup, cast(ubyte[])key.dup, () @trusted { return EVP_aes_128_cbc(); }() ).idup;
    }
}

private string decrypt(ubyte[] data, ubyte[] key, const(EVP_CIPHER)* cipher) @trusted {
    ubyte[] iv = data[0 .. 16];
    ubyte[] payload = data[16 .. $];

    auto ctx = EVP_CIPHER_CTX_new();
    if (ctx is null) {
        throw new Exception("Failed to create EVP cipher context - %s".format(getLastError));
    }
    scope(exit) EVP_CIPHER_CTX_free(ctx);

    EVP_DecryptInit(ctx, cipher, key.ptr, cast(const(ubyte)*)iv.ptr);

    ubyte[] buffer = new ubyte[payload.length];
    int updateLength = void;
    EVP_DecryptUpdate(ctx, buffer.ptr, &updateLength, payload.ptr, cast(int)payload.length);

    int finalLength = void;
    EVP_DecryptFinal(ctx, &buffer.ptr[updateLength], &finalLength);

    return cast(string)buffer[0 .. updateLength + finalLength];
}
