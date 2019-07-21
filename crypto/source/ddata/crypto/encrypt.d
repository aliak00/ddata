module ddata.crypto.encrypt;

import std.format: format;
import deimos.openssl.evp;
import ddata.common;
import ddata.crypto.algorithm;

version (OSX) {
    extern(C) @nogc nothrow private @system {
        void arc4random_buf(scope void* buf, size_t nbytes);
    }
}

private void randomFill(ubyte[] buffer) @trusted {
    // Shamelessly plucked from https://github.com/LightBender/SecureD/
    version (OSX) {
        arc4random_buf(buffer.ptr, buffer.length);
    } else version (Posix) {
        import std.stdio: File, _IONBF;
        try {
            File urandom = File("/dev/urandom", "rb");
            urandom.setvbuf(null, _IONBF);
            scope(exit) urandom.close();
            buffer = urandom.rawRead(buffer);
        } catch (Exception ex) {
            throw new Exception("failed to get random bytes - %s".format(ex.msg));
        }
    } else {
        static assert(0, "Unsupported OS for secure random byte generation");
    }
}

/**
    Encrypts a string using a key with the specified algorithm

    See_Also:
        `ddata.crypto.decrypt`
*/
public ubyte[] encrypt(const string data, const string key, Algorithm algorithm = Algorithm.aes128) @safe {
    final switch (algorithm) {
    case Algorithm.aes128:
        return encrypt(cast(const ubyte[])data, cast(const ubyte[])key, () @trusted { return EVP_aes_128_cbc(); }() );
    }
}

private ubyte[] encrypt(const ubyte[] data, const ubyte[] key, const(EVP_CIPHER)* cipher) @trusted {
    auto ctx = EVP_CIPHER_CTX_new();
    if (ctx is null) {
        throw new Exception("Failed to create EVP cipher context - %s".format(getLastError));
    }
    scope(exit) EVP_CIPHER_CTX_free(ctx);

    static ubyte[16] iv16;

    ubyte[] iv = void;
    int cipherBlockSize = EVP_CIPHER_block_size(cipher);
    switch (cipherBlockSize) {
    case 16:
        iv = iv16[];
        break;
    default:
        throw new Exception("Cannot handle cipher block size of %s".format(cipherBlockSize));
    }

    randomFill(iv);

    EVP_EncryptInit(ctx, cipher, key.ptr, cast(const(ubyte)*)iv.ptr);

    const bufferSize = data.length + cipherBlockSize;
    ubyte[] buffer = new ubyte[bufferSize];

    int updateLength = void;
    EVP_EncryptUpdate(ctx, buffer.ptr, &updateLength, data.ptr, cast(int)data.length);

    int finalLength = void;
    EVP_EncryptFinal(ctx, &buffer.ptr[updateLength], &finalLength);

    auto ret = iv ~ buffer[0 .. updateLength + finalLength];
    return ret;
}

@("should encrypt and decrypt to same message")
@safe unittest {
    import ddata.crypto: decrypt;
    string password = "some random password";
    string message = "this is a call to all you people how is this even happening";
    auto encryptedMessage = encrypt(message, password);
    auto decryptedMessage = decrypt(encryptedMessage, password);
    assert(message == decryptedMessage);
}

@("should test all algorithms for multiple text and password sizes")
@safe unittest {
    import std.range: generate, take, array;
    import std.random: uniform;
    import ddata.crypto: decrypt;

    alias genChars = generate!(() => cast(char)uniform(32, 127));

    int maxMessageLength = 2000;
    int maxPasswordLength = 200;
    int numSteps = 10;
    foreach (m; 0 .. maxMessageLength / numSteps) {
        foreach (p; 0 .. maxPasswordLength / numSteps) {
            int msize = (m + 1) * numSteps;
            int psize = (p + 1) * numSteps;

            string message = genChars.take(msize).array.idup;
            string password = genChars.take(psize).array.idup;

            auto encryptedMessage = encrypt(message, password);
            auto decryptedMessage = decrypt(encryptedMessage, password);
            assert(message == decryptedMessage);
        }
    }
}
