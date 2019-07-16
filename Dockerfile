FROM dlang2/ldc-ubuntu:1.15.0

WORKDIR /home/app/

COPY . .
RUN find . -name '*.d' -delete
RUN echo 'void main() { import std.stdio; writeln("hi"); }' > source/app.d

RUN dub upgrade --missing-only && rm source/app.d

COPY . .

RUN dub test --nodeps