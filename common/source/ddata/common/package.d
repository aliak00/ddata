module ddata.common;

package(ddata) {
    import deimos.openssl.err;

    string getLastError() @trusted {
        import std.string: toStringz;
        auto buffer = new char[120];
        buffer[] = '\0';
        ERR_error_string(ERR_get_error, buffer.ptr);
        return cast(string)buffer;
    }
}

version (unittest) {
    package(ddata) import std.stdio: writeln;
}
