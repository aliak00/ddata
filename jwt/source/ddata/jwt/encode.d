module ddata.jwt.encode;

import std.json;
import std.base64;

import ddata.jwt.algorithm;
import ddata.jwt.sign;

/**
    Encodes a jwt with the current payload and specified algorithm
*/
public string encode(const ref JSONValue payload, string key, Algorithm algorithm = Algorithm.hs256, JSONValue header = null) @safe {
    return encode(cast(ubyte[]) payload.toString().dup, key, algorithm, header);
}

private string encode(in ubyte[] payload, string key, Algorithm algorithm = Algorithm.hs256, JSONValue header = null) @safe {
    if (header.type == JSONType.null_) {
        header = (JSONValue[string]).init;
    }
    header["alg"] = cast(string) algorithm;
    header["typ"] = "JWT";

    const string encodedHeader = Base64URLNoPadding.encode(cast(ubyte[]) header.toString().dup);
    const string encodedPayload = Base64URLNoPadding.encode(payload);

    const string signingInput = encodedHeader ~ "." ~ encodedPayload;
    const string signatureInput = sign(signingInput, key, algorithm);
    const string signature = Base64URLNoPadding.encode(cast(ubyte[]) signatureInput.dup);

    return signingInput ~ "." ~ signature;
}

@("should encode json data in to jwt with private rsa key")
@safe unittest {
    immutable key = q"EOS
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAx80KNM7esDMCGwcLkJfvhLKBZtE1WuS+Q49jNSRDJt/nR2jS
0X3lkrT5rTR2l3JQiQ2a7X5mXznOiv/zgs07/wxnBFiCm93NTgaoP/iyRt7oiuN4
lwnQd4x8VlPPFt8+FEAF8LjmesqOFxvb2utXhnm72gBiV0KVcT8OJ880jyyn/sx+
lm2KAQE1dtDLPv2iR+oHeX34pHdaF2Pn5LvmkYLutFUB/jWbhUS6G5grns5QvCPF
7iI9KvplOn9n/cGNjGuu+686Sa4eWR96jsTi3ubvZpPio13rgaPpj3bp0NiQgOn5
OtPFiE/tqBuJRFnRL8rKsJeIV2RriqtyyPX/qQIDAQABAoIBAQCQw2LtuCVpDMwt
wQEEFtGYF63iTRqXbLzePnnm+wsck4YDG1QELW+0yCNO94AlYtIvOwhRow+RV1Tr
KV/KGeGqfdX2NBsNy7sBGZm2H/8rkj5ywzWQWbANrmA4PCkDrWRRT8H+FDoKJdCl
ta2qBHI6IOGWpkiaaMfWcZVUCrFOOgcJwz0FGUiH++gfRyOTiXmTd2VK6Yx8K3o5
PyETxOFb5Ct4OUvhWerxz6VW5s1wE9rUMjinTgkhBFNK0ya+Tilihq8sPWRq3C75
kBsW8gKOE9quOWYHslXHIEmhCdf36SoZPEzb3GLHuPPvXtMo2PG7EU7SqnnBw9qU
IBi2qlIBAoGBAPzVFjGAn1oQeP7j5ATW2bf/hmLFaDZtazO2d38K1MIBm0IftYPv
/33QM9GtnkGbApD7bKB28TgZ4tz/RxVu0T4CAU1Xnk+HMZZvaIUlMXQayhZMudFs
UCql1t0vZYV+7DinODlEBYu0J9Gxs+Xtu+GvsP9wGJIkpHOB8tn5vurZAoGBAMpN
3VcyihNhZtnvNMmKd2NNJl9m8+IOuIdld2fzjg0S0Z3Oadv6pGCKB5MlsGWLzOXb
sBGCdJ/NSIFFNouyu2Q3zI70gEalwieogbBuOmHOEBPPy/DRetfybumP2/KvCRQk
9yKfsnqWnHSB35dknLbIsbtbylnqC4gGVaE/gplRAoGATxEYWqy9qL3ECPodocHK
3nbDgPn5KCQ5xTdH0WwCsxUrh5dA/Zy9Sowk2GqyNhQSzmJCS0BHGWNHBhOzGCnK
t9iKrbQ75uUBhekbR6AlAgkqr6SY67wyqdOpCQy8c+4IU4M/2vDBxzm0xigLeVlK
Sz7VXFyi4nkhEJpP5wjqQqkCgYEAuXAASNJ5wGQS7AeZInh7ERoB54cuXHNT8EAw
4Kde+Vrbq8QuQscP77H2WYo9lAc+jR//1zz2fBimsl/oLMtre+St7AfwoVGFk+ag
4kFX4JkLIa3i6d6KtPFze0IzwdNyBfYQVrt91WLDDQSTGGnQQLfcOrpb1Gl1onzz
9veJVdECgYEA3/YfFzB7MjWxTtmlgyv5VdOuLLxkw0KV7QhoOv5zbwp9GsJFJWxN
OE6Trrq1EYQRe/NqdIRNt9tJMxLV+0E8s8kvT2yQPHvOWxV6lq0O5ypFeBT7wnXp
aLVVG9//pbbfefHaMZ4A98GT1b7e08Q/QX89cTUORvaQCM7E7QNqLoo=
-----END RSA PRIVATE KEY-----
EOS";

    immutable expectedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        ~ "eyJleHAiOjYwMCwiaWF0IjowLCJpc3MiOjExMTF9.WSERqrEL5JSoNO-"
        ~ "B_G6wt0pGFPYIN3WfTbjMZQEZHznLMkWPqGoQL_iWcF2QHKKVxLUxJTm"
        ~ "fONccSodJ2j6zQMlmdbU9LXa-DzwZTUYLLP6GiQrFv1IgTiFngjJQ32z"
        ~ "L6I2SIwMFiPBxyFImku_xrsT2MZu9J6N-VyPqM0LJ6nYPsKso-Nlo-iw"
        ~ "2PRh01YF5_rrxT8q45lOvHkflyZogESb8BaiJMZqscbey1TmDQq1TgiD"
        ~ "HRIHzuB3SBQa5E2s24cs9VSIOrnJJeUuWiVTYQrY9c5nwR_xT2W_rHsT"
        ~ "Pp2sEVePvIQJOfzu8iTraveKF4U0IliUI_wNYytiOVHnovg";

    const payload = `{"iat": 0, "exp": 600, "iss": 1111}`;
    const json = parseJSON(payload);
    const jwt = encode(json, key, Algorithm.rs256);

    assert(jwt == expectedJwt);
}
