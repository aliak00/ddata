module ddata.jwt.sign;

import std.format;

import deimos.openssl.pem;
import deimos.openssl.rsa;
import deimos.openssl.hmac;
import deimos.openssl.sha;
import deimos.openssl.err;

import ddata.jwt.algorithm;

private string getLastError() @trusted {
    import std.string: toStringz;
    auto buffer = new char[120];
    buffer[] = '\0';
    ERR_error_string(ERR_get_error, buffer.ptr);
    return cast(string)buffer;
}

private string signHs(string message, string key, uint digestLength, const(EVP_MD)* evp) @trusted {
    auto signedData = new ubyte[digestLength];

    auto ctx = HMAC_CTX_new();
    if (ctx is null) {
        throw new Exception("Failed to create HMAC context");
    }
    scope(exit) HMAC_CTX_free(ctx);

    if (!HMAC_Init_ex(ctx, key.ptr, cast(int)key.length, evp, null)) {
        throw new Exception("Failed to initialize HMAC context - %s".format(getLastError));
    }
    if (!HMAC_Update(ctx, cast(const(ubyte)*)message.ptr, cast(ulong)message.length)) {
        throw new Exception("Failed to update HMAC - %s".format(getLastError));
    }
    if (!HMAC_Final(ctx, cast(ubyte*)signedData.ptr, &digestLength)) {
        throw new Exception("Failed to finalize HMAC - %s".format(getLastError));
    }

    return cast(string)signedData;
}

private string signRs(string message, string key, uint digestLength, int type) @trusted {
    auto sha256 = new ubyte[digestLength];
    SHA256(cast(const(ubyte)*)message.ptr, message.length, sha256.ptr);

    auto signedData = new ubyte[digestLength * 8];

    RSA* ctx = RSA_new();
    if (ctx is null) {
        throw new Exception("Failed to create RSA context - %s".format(getLastError));
    }
    scope(exit) RSA_free(ctx);

    BIO* bio = BIO_new_mem_buf(cast(char*)key.ptr, cast(int)key.length);
    if (bio is null) {
        throw new Exception("Failed to load key in memory bio - %s".format(getLastError));
    }
    scope(exit) BIO_free(bio);

    RSA* rsaPrivate = PEM_read_bio_RSAPrivateKey(bio, &ctx, null, null);
    if(rsaPrivate is null) {
        throw new Exception("Failed to create RSA private key - %s".format(getLastError));
    }
    if (!RSA_sign(type, cast(const(ubyte)*)sha256.ptr, digestLength, signedData.ptr, &digestLength, rsaPrivate)) {
        throw new Exception("Failed to sign RSA message digest - %s".format(getLastError));
    }

    return cast(string)signedData;
}

package string sign(string message, string key, Algorithm algorithm = Algorithm.hs256) @safe {    
    final switch (algorithm) {
        case Algorithm.hs256:
            return signHs(message, key, SHA256_DIGEST_LENGTH, () @trusted { return EVP_sha256(); } ());
        case Algorithm.rs256: {
            return signRs(message, key, SHA256_DIGEST_LENGTH, NID_sha256);
        }
    }
}
