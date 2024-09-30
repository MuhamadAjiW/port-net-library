# Library C Net Monitoring
### How To Compile

In order to compile this project do

- ./autogen.sh
- make

To compile the library w/o any tools or tests:

- ./autogen.sh --with-only-libndpi
- make

To run tests do additionally:

- ./tests/do.sh # Generate and check for diff's in PCAP files
- ./tests/do-unit.sh # Run unit tests
- ./tests/do-dga.sh # Run DGA detection test

or run all with: `make check`

after test you can run: `./ndpiReader -i <interface>`

Please note that the (minimal) pre-requisites for compilation include:
- GNU tools (autoconf automake libtool pkg-config gettext flex bison)
- GNU C compiler (gcc) or Clang