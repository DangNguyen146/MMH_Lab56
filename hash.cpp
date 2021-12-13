
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

// def functions
wstring in2ws(const CryptoPP::Integer &t);
string ws2s(const std::wstring &str);
wstring s2ws(const std::string &str);
wstring OpenandReadFile(const char *filename);
wstring OpenandReadFile(const char *filename);

void SHA224_hashing(wstring message, string &digest);
void SHA256_hashing(wstring message, string &digest);
void SHA384_hashing(wstring message, string &digest);
void SHA512_hashing(wstring message, string &digest);
void SHA3_224_hashing(wstring message, string &digest);
void SHA3_256_hashing(wstring message, string &digest);
void SHA3_384_hashing(wstring message, string &digest);
void SHA3_512_hashing(wstring message, string &digest);
void SHAKE128_hashing(wstring message, string &digest, int d);
void SHAKE256_hashing(wstring message, string &digest, int d);

int main(int argc, char *argv[])
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
    int mode;
    wstring message;

    wcout << L"Lựa chọn đầu vào:\n"
          << L"(1)Từ màn hình\t" << L"(2)Từ file\n>> ";
    wcin >> mode;
    wcin.ignore();
    switch (mode)
    {
    case 1:
        wcout << "Please input message:";
        fflush(stdin);
        getline(wcin, message);
        break;
    case 2:
        message = OpenandReadFile("plaintext.txt");
        break;
    }
    int category;
    wcout << L"Lựa chọn loại HASH:\n"
          << L"(1)SHA224\t" << L"(2)SHA256\t" << L"(3)SHA384\t" << L"(4)SHA512\t" << L"(5)SHA3-224\t" << L"(6)SHA3-256\t" << L"(7)SHA3-384\t" << L"(8)SHA3-512\t" << L"(9)SHAKE128\t" << L"(10)SHAKE256\n>>";
    wcin >> category;
    wcin.ignore();
    string encode;
    switch (category)
    {
    case 1:
    {
        CryptoPP::SHA224 hash;
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHA224_hashing(message, digest);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    case 2:
    {
        CryptoPP::SHA256 hash;
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHA256_hashing(message, digest);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    case 3:
    {
        CryptoPP::SHA384 hash;
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHA384_hashing(message, digest);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    case 4:
    {
        CryptoPP::SHA512 hash;
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHA512_hashing(message, digest);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    case 5:
    {
        CryptoPP::SHA3_224 hash;
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHA3_224_hashing(message, digest);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    case 6:
    {
        CryptoPP::SHA3_256 hash;
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHA3_256_hashing(message, digest);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    case 7:
    {
        CryptoPP::SHA3_384 hash;
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHA3_384_hashing(message, digest);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    case 8:
    {
        CryptoPP::SHA3_512 hash;
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHA3_512_hashing(message, digest);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    case 9:
    {
        int d;
        wcout << L"Nhập độ dài >0: ";
        wcin >> d;
        wcin.ignore();

        CryptoPP::SHAKE128 hash(d);
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHAKE128_hashing(message, digest, d);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    case 10:
    {
        int d;
        wcout << L"Nhập độ dài >0: ";
        wcin >> d;
        wcin.ignore();

        CryptoPP::SHAKE256 hash(d);
        wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
        wcout << "Digest size: " << hash.DigestSize() << endl;
        wcout << "Block size: " << hash.BlockSize() << endl;

        string digest;
        int startCount = clock();
        for (int i = 0; i < 10000; i++)
        {
            SHAKE256_hashing(message, digest, d);
        }
        int stopCount = clock();
        double total = (stopCount - startCount) / double(CLOCKS_PER_SEC) * 1000;
        wcout << "Message: " << message << endl;
        wcout << "Digest: ";
        encode.clear();
        StringSource(digest, true,
                     new HexEncoder(new StringSink(encode)));
        wcout << s2ws(encode) << endl;

        wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
        wcout << "\nExecution time: " << total / 10000 << " ms" << endl
              << endl;
        break;
    }
    }
    // Hash to Z_p
    string wdigest = encode + "H";
    CryptoPP::Integer idigest(wdigest.data());
    CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
    wcout << "Prime number p for Z_p: " << in2ws(p) << endl;
    wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << endl;
    return 0;
}
/* convert string to wstring */
wstring s2ws(const string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string ws2s(const wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

wstring in2ws(const CryptoPP::Integer &t)
{
    ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    string encoded(oss.str());
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}
wstring OpenandReadFile(const char *filename)
{
    std::wifstream wif(filename);
    wif.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
    std::wstringstream wss;
    wss << wif.rdbuf();
    return wss.str();
}
void SHA224_hashing(wstring message, string &digest)
{
    CryptoPP::SHA224 hash;
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}
void SHA256_hashing(wstring message, string &digest)
{
    CryptoPP::SHA256 hash;
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}
void SHA384_hashing(wstring message, string &digest)
{
    CryptoPP::SHA384 hash;
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}
void SHA512_hashing(wstring message, string &digest)
{
    CryptoPP::SHA512 hash;
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}
void SHA3_224_hashing(wstring message, string &digest)
{
    CryptoPP::SHA3_224 hash;
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}
void SHA3_256_hashing(wstring message, string &digest)
{
    CryptoPP::SHA3_256 hash;
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}
void SHA3_384_hashing(wstring message, string &digest)
{
    CryptoPP::SHA3_384 hash;
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}
void SHA3_512_hashing(wstring message, string &digest)
{
    CryptoPP::SHA3_512 hash;
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}
void SHAKE128_hashing(wstring message, string &digest, int d)
{
    CryptoPP::SHAKE128 hash(d);
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(d);
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}
void SHAKE256_hashing(wstring message, string &digest, int d)
{
    CryptoPP::SHAKE256 hash(d);
    hash.Restart();
    hash.Update((const byte *)ws2s(message).data(), ws2s(message).size());
    digest.resize(d);
    hash.TruncatedFinal((byte *)&digest[0], digest.size());
}