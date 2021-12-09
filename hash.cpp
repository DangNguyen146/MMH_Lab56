#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

// Integer arithmetics
// #include <cryptopp/integer.h>
// #include <cryptopp/nbtheory.h>

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
using  std::codecvt_utf8;
wstring s2ws (const std::string& str);
string ws2s (const std::wstring& str);

// #include "cryptopp/cryptlib.h"

// Header for hash funtion SHA3 (SHA3_224, SHA3_256, SHA3_384, SHA3_512 )
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>


#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
// input, output string
#include <cryptopp/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::Redirector;
// input, output file
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::byte;

// Convert integer to wstring
#include <sstream>
using std::ostringstream;

//def functions
wstring in2ws (const CryptoPP::Integer& t);
string ws2s(const std::wstring& str);
wstring s2ws(const std::string& str);


int main (int argc, char* argv[])
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
    // Hash algorithm
    CryptoPP::SHAKE256 hash;
  
    // Print algorithm information
    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    // Input message
    std::wstring message;
    std::wcout << "Please input message:";
    std::getline(std::wcin,message);
    // Compute disgest
    std::string digest;
    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    digest.resize(1024);
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    std::wcout << "Message: " << message << std::endl;
    std::wcout << "Digest: ";
    std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    std::wcout << s2ws(encode) << std::endl;
    // Hash to Z_p
    string wdigest=encode+"H";
    CryptoPP::Integer idigest(wdigest.data());
    CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
    wcout << "Prime number p for Z_p: "<< in2ws(p) << endl;
    wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << endl;
    return 0;
}
/* convert string to wstring */
wstring s2ws(const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string ws2s(const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

wstring in2ws (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}