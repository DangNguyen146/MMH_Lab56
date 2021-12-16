
// Integer arithmetics
// #include <cryptopp/integer.h>
// #include <cryptopp/nbtheory.h>

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
wstring s2ws(const std::string &str);
string ws2s(const std::wstring &str);

// #include "cryptopp/cryptlib.h"

// Header for hash funtion SHA3 (SHA224, SHA256, SHA384, SHA512 )
#include <cryptopp/sha.h>
// Header for hash funtion (SHAKE128, SHAKE256)
#include <cryptopp/shake.h>
// Header for hash funtion SHA3 (SHA3_224, SHA3_256, SHA3_384, SHA3_512 )
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
// input, output string
#include <cryptopp/filters.h>
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
// input, output file
#include <cryptopp/files.h>
using CryptoPP::byte;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

// Convert integer to wstring
#include <sstream>
using std::ostringstream;

//def functions
wstring in2ws(const CryptoPP::Integer &t);
string ws2s(const std::wstring &str);
wstring s2ws(const std::string &str);

int main(int argc, char *argv[])
{
//Linux cần 2 gạch để xuất tiếng việt
#ifdef linux
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
    // Hash algorithm
    CryptoPP::SHA256 hash;

    // Print algorithm information
    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;

    string message, digest, exmessage, key, padding, input;
    wstring messages, exmessages, keys;
    wcout << "Please input message:";
    fflush(stdin);
    getline(wcin, messages);
    message=ws2s(messages);

    wcout << "Please input exmessage:";
    fflush(stdin);
    getline(wcin, exmessages);
    exmessage=ws2s(exmessages);

    padding = "80000000000000000000000000000000000000000000000000000000000000000000e8";
    wcout << "Please input key:";
    fflush(stdin);
    getline(wcin, keys);
    key=ws2s(keys);


    string hmessage, hexmessage, hkey;
    StringSource(message, true, new HexEncoder(new StringSink(hmessage)));
    StringSource(exmessage, true, new HexEncoder(new StringSink(hexmessage)));
    StringSource(key, true, new HexEncoder(new StringSink(hkey)));
    StringSource(hkey + hmessage + padding + hexmessage, true, new HexDecoder(new StringSink(input)));

    hash.Restart();
    hash.Update((const byte *)input.data(), input.size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte *)&digest[0], digest.size());

    // Pretty print digest
    std::wcout << "Digest exmessage: ";
    std::string encode;
    encode.clear();
    StringSource(digest, true,
                 new HexEncoder(new StringSink(encode)));
    string temp1 = encode;
    std::wcout << s2ws(temp1) << std::endl;

    return 0;
}
/* convert string to wstring */
wstring s2ws(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string ws2s(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

wstring in2ws(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}