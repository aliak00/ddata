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

    auto msg = "76d3beec63f0dc9204c3a102d2d3db86200d57cf"
        .decrypt("some-key", Algorithm.aes128)
        .collectExceptionMsg;
    assert(msg.canFind("Failed to finalize evp contex"));

    string password = "some random password";
    string message = "this is a call to all you people how is this even happening";
    auto encryptedMessage = encrypt(message, password);
    auto decryptedMessage = decrypt(encryptedMessage, password);
    assert(message == decryptedMessage);
}
