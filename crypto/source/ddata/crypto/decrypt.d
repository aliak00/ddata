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
public string decrypt(const ubyte[] data, const string key, Algorithm algorithm = Algorithm.aes128) @safe {
    final switch (algorithm) {
    case Algorithm.aes128:
        return decrypt(data, cast(const ubyte[])key, () @trusted { return EVP_aes_128_cbc(); }() ).idup;
    }
}

/// Ditto
public string decrypt(const string data, const string key, Algorithm algorithm = Algorithm.aes128) @safe {
    final switch (algorithm) {
    case Algorithm.aes128:
        return decrypt(cast(immutable ubyte[])data, cast(const ubyte[])key, () @trusted { return EVP_aes_128_cbc(); }() ).idup;
    }
}

private string decrypt(const ubyte[] data, const ubyte[] key, const(EVP_CIPHER)* cipher) @trusted {
    const iv = data[0 .. 16];
    const payload = data[16 .. $];

    auto ctx = EVP_CIPHER_CTX_new();
    if (ctx is null) {
        throw new Exception("Failed to create EVP cipher context - %s".format(getLastError));
    }
    scope(exit) EVP_CIPHER_CTX_free(ctx);

    if (!EVP_DecryptInit(ctx, cipher, key.ptr, cast(const(ubyte)*)iv.ptr)) {
        throw new Exception("Failed to initialize evp context - %s".format(getLastError));
    }

    ubyte[] buffer = new ubyte[payload.length];
    int updateLength = void;
    if (!EVP_DecryptUpdate(ctx, buffer.ptr, &updateLength, payload.ptr, cast(int)payload.length)) {
        throw new Exception("Failed to update evp context - %s".format(getLastError));
    }

    int finalLength = void;
    if (!EVP_DecryptFinal(ctx, &buffer.ptr[updateLength], &finalLength)) {
        throw new Exception("Failed to finalize evp context - %s".format(getLastError));
    }

    return cast(string)buffer[0 .. updateLength + finalLength];
}

@("decryption should handle failure gracefully")
unittest {
    import std.exception: collectExceptionMsg;
    import std.algorithm: canFind;
    import ddata.crypto: encrypt;

    auto msg = (cast(ubyte[])"76d3beec63f0dc9204c3a102d2d3db86200d57cf")
        .decrypt("some-key", Algorithm.aes128)
        .collectExceptionMsg;
    assert(msg.canFind("Failed to finalize evp contex"));

    const password = "some random password";
    const message = "this is a call to all you people how is this even happening";
    const encryptedMessage = encrypt(message, password);
    const decryptedMessage = decrypt(encryptedMessage, password);
    assert(message == decryptedMessage);
}


@("Should be able to base64 an encryption and then decrypt")
unittest {
    import std.base64: Base64;
    import ddata.crypto: encrypt;
    const str = "0aecba4fe377338b94746e203b4718c4cfdb7629";
    const password = "password";
    const encrypted = str.encrypt(password, Algorithm.aes128);
    const base64Encoded = Base64.encode(encrypted);
    const base64Decoded = Base64.decode(base64Encoded);
    const decrypted = base64Decoded.decrypt(password, Algorithm.aes128);
    assert(str == decrypted);
}
