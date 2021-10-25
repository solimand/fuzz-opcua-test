#  Python useful modules

## struct [3.10] — Interpret bytes as packed binary data

    Source code: Lib/struct.py

This module performs conversions between Python values and C structs represented as Python bytes objects. This can be used in handling binary data stored in files or from network connections, among other sources. It uses Format Strings as compact descriptions of the layout of the C structs and the intended conversion to/from Python values.

Note: By default, the result of packing a given C struct includes pad bytes in order to maintain proper alignment for the C types involved; similarly, alignment is taken into account when unpacking. This behavior is chosen so that the bytes of a packed struct correspond exactly to the layout in memory of the corresponding C struct. To handle platform-independent data formats or omit implicit pad bytes, use standard size and alignment instead of native size and alignment: see Byte Order, Size, and Alignment for details.

Several struct functions (and methods of Struct) take a buffer argument. This refers to objects that implement the Buffer Protocol and provide either a readable or read-writable buffer. The most common types used for that purpose are bytes and bytearray, but many other types that can be viewed as an array of bytes implement the buffer protocol, so that they can be read/filled without additional copying from a bytes object.


1. ``` exception struct.error ```
    Exception raised on various occasions; argument is a string describing what is wrong.


2. ```struct.pack(format, v1, v2, ...)```
    Return a bytes object containing the values v1, v2, … packed according to the format string format. The arguments must match the values required by the format exactly.

3. ```struct.unpack(format, buffer) ```
    Unpack from the buffer buffer (presumably packed by pack(format, ...)) according to the format string format. The result is a tuple even if it contains exactly one item. The buffer’s size in bytes must match the size required by the format, as reflected by calcsize().

### Format Strings
By default, C types are represented in the machine’s native format and byte order, and properly aligned by skipping pad bytes if necessary (according to the rules used by the C compiler).

Alternatively, the first character of the format string can be used to indicate the byte order, size and alignment of the packed data, according to the following table:

| Character |       Byte order       |   Size   | Alignment |
|:---------:|:----------------------:|:--------:|:---------:|
| @         | native                 | native   | native    |
| =         | native                 | standard | none      |
| <         | little-endian          | standard | none      |
| >         | big-endian             | standard | none      |
| !         | network (= big-endian) | standard | none      |

* If the first character is not one of these, '@' is assumed. 
* Native byte order is big-endian or little-endian, depending on the host system. For example, Intel x86 and AMD64 (x86-64) are little-endian; Motorola 68000 and PowerPC G5 are big-endian; ARM and Intel Itanium feature switchable endianness (bi-endian). Use sys.byteorder to check the endianness of your system.


### Format Chars
The ‘Standard size’ column refers to the size of the packed value in bytes when using standard size; that is, when the format string starts with one of '<', '>', '!' or '='. When using native size, the size of the packed value is platform-dependent.

| Format |       C Type       |    Python type    | Standard size |   Notes  |
|:------:|:------------------:|:-----------------:|:-------------:|:--------:|
| x      | pad byte           | no value          |               |          |
| c      | char               | bytes of length 1 | 1             |          |
| b      | signed char        | integer           | 1             | (1), (2) |
| B      | unsigned char      | integer           | 1             | (2)      |
| ?      | _Bool              | bool              | 1             | (1)      |
| h      | short              | integer           | 2             | (2)      |
| H      | unsigned short     | integer           | 2             | (2)      |
| i      | int                | integer           | 4             | (2)      |
| I      | unsigned int       | integer           | 4             | (2)      |
| l      | long               | integer           | 4             | (2)      |
| L      | unsigned long      | integer           | 4             | (2)      |
| q      | long long          | integer           | 8             | (2)      |
| Q      | unsigned long long | integer           | 8             | (2)      |
| n      | ssize_t            | integer           |               | (3)      |
| N      | size_t             | integer           |               | (3)      |
| e      | (6)                | float             | 2             | (4)      |
| f      | float              | float             | 4             | (4)      |
| d      | double             | float             | 8             | (4)      |
| s      | char[]             | bytes             |               |          |
| p      | char[]             | bytes             |               |          |
| P      | void*              | integer           |               | (5)      |

