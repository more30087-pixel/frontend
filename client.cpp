#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

#ifndef CALG_AES_256
#define CALG_AES_256 0x00006610
#endif

#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif


// =========================================
// SEND ALL
// =========================================

bool sendAll(
    SOCKET socket,
    const char* buffer,
    int totalBytes)
{
    int sentBytes = 0;

    while (sentBytes < totalBytes)
    {
        int result = send(
            socket,
            buffer + sentBytes,
            totalBytes - sentBytes,
            0
        );

        if (result == SOCKET_ERROR)
        {
            return false;
        }

        sentBytes += result;
    }

    return true;
}


// =========================================
// RECEIVE ALL
// =========================================

bool recvAll(
    SOCKET socket,
    char* buffer,
    int totalBytes)
{
    int receivedBytes = 0;

    while (receivedBytes < totalBytes)
    {
        int result = recv(
            socket,
            buffer + receivedBytes,
            totalBytes - receivedBytes,
            0
        );

        if (result <= 0)
        {
            return false;
        }

        receivedBytes += result;
    }

    return true;
}


// =========================================
// SEND UINT64
// =========================================

bool sendUint64(
    SOCKET socket,
    uint64_t value)
{
    uint32_t high =
        htonl(
            (uint32_t)(value >> 32)
        );

    uint32_t low =
        htonl(
            (uint32_t)(value & 0xFFFFFFFF)
        );

    if (!sendAll(
            socket,
            (char*)&high,
            sizeof(high)))
    {
        return false;
    }

    if (!sendAll(
            socket,
            (char*)&low,
            sizeof(low)))
    {
        return false;
    }

    return true;
}


// =========================================
// SEND STRING
// =========================================

bool sendString(
    SOCKET socket,
    const string& text)
{
    uint32_t length =
        (uint32_t)text.length();

    uint32_t lengthNetwork =
        htonl(length);

    if (!sendAll(
            socket,
            (char*)&lengthNetwork,
            sizeof(lengthNetwork)))
    {
        return false;
    }

    if (!sendAll(
            socket,
            text.c_str(),
            length))
    {
        return false;
    }

    return true;
}


// =========================================
// RECEIVE STRING
// =========================================

bool receiveString(
    SOCKET socket,
    string& text)
{
    uint32_t lengthNetwork;

    if (!recvAll(
            socket,
            (char*)&lengthNetwork,
            sizeof(lengthNetwork)))
    {
        return false;
    }

    uint32_t length =
        ntohl(lengthNetwork);

    if (length > 1000)
    {
        return false;
    }

    char buffer[1001];

    if (!recvAll(
            socket,
            buffer,
            length))
    {
        return false;
    }

    buffer[length] = '\0';

    text = buffer;

    return true;
}


// =========================================
// CREATE SHA-256 OF STRING
// =========================================

bool calculateStringSHA256(
    const string& text,
    string& hashResult)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
    {
        return false;
    }

    if (!CryptCreateHash(
            hProv,
            CALG_SHA_256,
            0,
            0,
            &hHash))
    {
        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    if (!CryptHashData(
            hHash,
            (BYTE*)text.c_str(),
            (DWORD)text.length(),
            0))
    {
        CryptDestroyHash(hHash);

        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    BYTE hash[32];

    DWORD hashSize =
        sizeof(hash);

    if (!CryptGetHashParam(
            hHash,
            HP_HASHVAL,
            hash,
            &hashSize,
            0))
    {
        CryptDestroyHash(hHash);

        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    stringstream ss;

    for (DWORD i = 0;
         i < hashSize;
         i++)
    {
        ss << hex
           << setw(2)
           << setfill('0')
           << (int)hash[i];
    }

    hashResult =
        ss.str();

    CryptDestroyHash(hHash);

    CryptReleaseContext(
        hProv,
        0);

    return true;
}


// =========================================
// CREATE AUTHENTICATION HASH
// =========================================

bool createAuthenticationHash(
    const string& password,
    const BYTE challenge[32],
    string& result)
{
    string challengeData;

    for (int i = 0; i < 32; i++)
    {
        challengeData +=
            (char)challenge[i];
    }

    string authenticationData =
        password +
        challengeData;

    return calculateStringSHA256(
        authenticationData,
        result);
}


// =========================================
// CREATE AES-256 KEY
// =========================================

bool createAESKey(
    HCRYPTPROV hProv,
    HCRYPTKEY& hKey)
{
    BYTE keyData[32] =
    {
        0x10, 0x21, 0x32, 0x43,
        0x54, 0x65, 0x76, 0x87,
        0x98, 0xA9, 0xBA, 0xCB,
        0xDC, 0xED, 0xFE, 0x0F,

        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC,
        0xDD, 0xEE, 0xFF, 0x00
    };

    BYTE keyBlob[
        sizeof(BLOBHEADER)
        + sizeof(DWORD)
        + 32
    ];

    BLOBHEADER* header =
        (BLOBHEADER*)keyBlob;

    header->bType =
        PLAINTEXTKEYBLOB;

    header->bVersion =
        CUR_BLOB_VERSION;

    header->reserved =
        0;

    header->aiKeyAlg =
        CALG_AES_256;

    DWORD* keyLength =
        (DWORD*)(
            keyBlob +
            sizeof(BLOBHEADER)
        );

    *keyLength = 32;

    BYTE* keyBytes =
        keyBlob +
        sizeof(BLOBHEADER)
        + sizeof(DWORD);

    memcpy(
        keyBytes,
        keyData,
        32
    );

    if (!CryptImportKey(
            hProv,
            keyBlob,
            sizeof(keyBlob),
            0,
            0,
            &hKey))
    {
        return false;
    }

    return true;
}


// =========================================
// GENERATE RANDOM IV
// =========================================

bool generateIV(
    HCRYPTPROV hProv,
    BYTE iv[16])
{
    if (!CryptGenRandom(
            hProv,
            16,
            iv))
    {
        return false;
    }

    return true;
}


// =========================================
// CALCULATE SHA-256 OF FILE
// =========================================

bool calculateSHA256(
    const string& fileName,
    string& hashResult)
{
    ifstream file(
        fileName,
        ios::binary
    );

    if (!file)
    {
        return false;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
    {
        return false;
    }

    if (!CryptCreateHash(
            hProv,
            CALG_SHA_256,
            0,
            0,
            &hHash))
    {
        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    char buffer[4096];

    while (
        file.read(
            buffer,
            sizeof(buffer))
        ||
        file.gcount() > 0)
    {
        DWORD bytesRead =
            (DWORD)file.gcount();

        if (!CryptHashData(
                hHash,
                (BYTE*)buffer,
                bytesRead,
                0))
        {
            CryptDestroyHash(hHash);

            CryptReleaseContext(
                hProv,
                0);

            file.close();

            return false;
        }
    }

    file.close();

    BYTE hash[32];

    DWORD hashSize =
        sizeof(hash);

    if (!CryptGetHashParam(
            hHash,
            HP_HASHVAL,
            hash,
            &hashSize,
            0))
    {
        CryptDestroyHash(hHash);

        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    stringstream ss;

    for (DWORD i = 0;
         i < hashSize;
         i++)
    {
        ss << hex
           << setw(2)
           << setfill('0')
           << (int)hash[i];
    }

    hashResult =
        ss.str();

    CryptDestroyHash(hHash);

    CryptReleaseContext(
        hProv,
        0);

    return true;
}


// =========================================
// ENCRYPT FILE
// =========================================

bool encryptFile(
    const string& inputFileName,
    const string& outputFileName,
    HCRYPTKEY hKey)
{
    ifstream input(
        inputFileName,
        ios::binary
    );

    if (!input)
    {
        return false;
    }

    ofstream output(
        outputFileName,
        ios::binary
    );

    if (!output)
    {
        input.close();
        return false;
    }

    char buffer[4112];

    while (true)
    {
        input.read(
            buffer,
            4096
        );

        DWORD dataLength =
            (DWORD)input.gcount();

        if (dataLength == 0)
        {
            break;
        }

        bool isFinal = false;

        if (input.peek() == EOF)
        {
            isFinal = true;
        }

        DWORD bufferLength =
            sizeof(buffer);

        if (!CryptEncrypt(
                hKey,
                0,
                isFinal,
                0,
                (BYTE*)buffer,
                &dataLength,
                bufferLength))
        {
            cout << "AES encryption failed!"
                 << endl;

            input.close();
            output.close();

            return false;
        }

        output.write(
            buffer,
            dataLength
        );

        if (isFinal)
        {
            break;
        }
    }

    input.close();
    output.close();

    return true;
}


// =========================================
// MAIN
// =========================================

int main()
{
    // =========================================
    // START WINSOCK
    // =========================================

    WSADATA wsa;

    if (WSAStartup(
            MAKEWORD(2, 2),
            &wsa) != 0)
    {
        cout << "Winsock startup failed!"
             << endl;

        return 1;
    }

    cout << "Winsock started successfully!"
         << endl;


    // =========================================
    // CREATE SOCKET
    // =========================================

    SOCKET clientSocket =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (clientSocket == INVALID_SOCKET)
    {
        cout << "Socket creation failed!"
             << endl;

        WSACleanup();

        return 1;
    }

    cout << "Client socket created successfully!"
         << endl;


    // =========================================
    // SERVER ADDRESS
    // =========================================

    sockaddr_in serverAddress;

    serverAddress.sin_family =
        AF_INET;

    serverAddress.sin_addr.s_addr =
        inet_addr("127.0.0.1");

    serverAddress.sin_port =
        htons(8080);


    // =========================================
    // CONNECT
    // =========================================

    cout << "Connecting to server..."
         << endl;

    if (connect(
            clientSocket,
            (sockaddr*)&serverAddress,
            sizeof(serverAddress)
        ) == SOCKET_ERROR)
    {
        cout << "Connection failed!"
             << endl;

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }

    cout << "Connected to server successfully!"
         << endl;


    // =========================================
    // AUTHENTICATION
    // =========================================

    string username =
        "admin";

    string password =
        "12345";


    // =========================================
    // SEND USERNAME
    // =========================================

    if (!sendString(
            clientSocket,
            username))
    {
        cout << "Failed to send username!"
             << endl;

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    cout << "Username sent."
         << endl;


    // =========================================
    // RECEIVE RANDOM CHALLENGE
    // =========================================

    BYTE challenge[32];

    if (!recvAll(
            clientSocket,
            (char*)challenge,
            32))
    {
        cout << "Failed to receive authentication challenge!"
             << endl;

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    cout << "Authentication challenge received."
         << endl;


    // =========================================
    // CREATE AUTHENTICATION HASH
    // =========================================

    string authenticationHash;

    if (!createAuthenticationHash(
            password,
            challenge,
            authenticationHash))
    {
        cout << "Could not create authentication hash!"
             << endl;

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }


    // =========================================
    // SEND AUTHENTICATION RESPONSE
    // =========================================

    if (!sendString(
            clientSocket,
            authenticationHash))
    {
        cout << "Failed to send authentication response!"
             << endl;

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    cout << "Authentication response sent."
         << endl;


    // =========================================
    // RECEIVE AUTHENTICATION RESULT
    // =========================================

    string response;

    if (!receiveString(
            clientSocket,
            response))
    {
        cout << "Failed to receive authentication result!"
             << endl;

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    cout << "Server response: "
         << response
         << endl;


    if (response != "AUTH_SUCCESS")
    {
        cout << "Login failed!"
             << endl;

        closesocket(clientSocket);

        WSACleanup();

        return 0;
    }

    cout << "Login successful!"
         << endl;


    // =========================================
    // OPEN ORIGINAL FILE
    // =========================================

    string fileName;

    cout << endl;

    cout << "Enter file name to send: ";

    cin >> fileName;


    ifstream testFile(
        fileName,
        ios::binary
    );

    if (!testFile)
    {
        cout << "Could not open file!"
             << endl;

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }

    testFile.close();


    cout << "File opened successfully: "
         << fileName
         << endl;


    // =========================================
    // CALCULATE ORIGINAL SHA-256
    // =========================================

    string originalHash;

    if (!calculateSHA256(
            fileName,
            originalHash))
    {
        cout << "Could not calculate SHA-256!"
             << endl;

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }

    cout << endl;

    cout << "Original file SHA-256:"
         << endl;

    cout << originalHash
         << endl;


    // =========================================
    // START CRYPTOGRAPHIC PROVIDER
    // =========================================

    HCRYPTPROV hProv = 0;

    if (!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
    {
        cout << "Cryptographic provider failed!"
             << endl;

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }


    // =========================================
    // CREATE AES KEY
    // =========================================

    HCRYPTKEY hKey = 0;

    if (!createAESKey(
            hProv,
            hKey))
    {
        cout << "AES key creation failed!"
             << endl;

        CryptReleaseContext(
            hProv,
            0);

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }

    cout << endl;

    cout << "AES-256 key created."
         << endl;


    // =========================================
    // GENERATE RANDOM IV
    // =========================================

    BYTE iv[16];

    if (!generateIV(
            hProv,
            iv))
    {
        cout << "IV generation failed!"
             << endl;

        CryptDestroyKey(hKey);

        CryptReleaseContext(
            hProv,
            0);

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }

    cout << "Random IV generated."
         << endl;


    // =========================================
    // SET AES IV
    // =========================================

    if (!CryptSetKeyParam(
            hKey,
            KP_IV,
            iv,
            0))
    {
        cout << "Failed to set AES IV!"
             << endl;

        CryptDestroyKey(hKey);

        CryptReleaseContext(
            hProv,
            0);

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }

    cout << "AES IV set successfully."
         << endl;


    // =========================================
    // ENCRYPT FILE
    // =========================================

    string encryptedFile =
        "encrypted_transfer.bin";

    cout << "Encrypting file..."
         << endl;

    if (!encryptFile(
            fileName,
            encryptedFile,
            hKey))
    {
        cout << "File encryption failed!"
             << endl;

        CryptDestroyKey(hKey);

        CryptReleaseContext(
            hProv,
            0);

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }

    cout << "File encrypted successfully!"
         << endl;


    // =========================================
    // CLOSE AES KEY
    // =========================================

    CryptDestroyKey(hKey);


    // =========================================
    // CLOSE CRYPTO PROVIDER
    // =========================================

    CryptReleaseContext(
        hProv,
        0);


    // =========================================
    // GET ENCRYPTED FILE SIZE
    // =========================================

    ifstream encryptedInput(
        encryptedFile,
        ios::binary
    );

    if (!encryptedInput)
    {
        cout << "Could not open encrypted file!"
             << endl;

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }

    encryptedInput.seekg(
        0,
        ios::end
    );

    uint64_t encryptedFileSize =
        encryptedInput.tellg();

    encryptedInput.seekg(
        0,
        ios::beg
    );

    cout << "Encrypted file size: "
         << encryptedFileSize
         << " bytes"
         << endl;


    // =========================================
    // SEND FILE NAME
    // =========================================

    if (!sendString(
            clientSocket,
            fileName))
    {
        cout << "Failed to send file name!"
             << endl;

        encryptedInput.close();

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }


    // =========================================
    // SEND AES IV
    // =========================================

    if (!sendAll(
            clientSocket,
            (char*)iv,
            16))
    {
        cout << "Failed to send AES IV!"
             << endl;

        encryptedInput.close();

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    cout << "AES IV sent to server."
         << endl;


    // =========================================
    // SEND ENCRYPTED FILE SIZE
    // =========================================

    if (!sendUint64(
            clientSocket,
            encryptedFileSize))
    {
        cout << "Failed to send encrypted file size!"
             << endl;

        encryptedInput.close();

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }


    // =========================================
    // SEND ENCRYPTED DATA
    // =========================================

    char buffer[4096];

    uint64_t totalSent = 0;

    while (
        encryptedInput.read(
            buffer,
            sizeof(buffer))
        ||
        encryptedInput.gcount() > 0)
    {
        int bytesRead =
            (int)encryptedInput.gcount();

        if (!sendAll(
                clientSocket,
                buffer,
                bytesRead))
        {
            cout << endl;

            cout << "Encrypted file transfer failed!"
                 << endl;

            encryptedInput.close();

            closesocket(clientSocket);
            WSACleanup();

            return 1;
        }

        totalSent +=
            bytesRead;

        cout << "\rEncrypted data sent: "
             << totalSent
             << " / "
             << encryptedFileSize
             << " bytes"
             << flush;
    }

    cout << endl;

    encryptedInput.close();

    cout << "Encrypted file transferred successfully!"
         << endl;


    // =========================================
    // SEND ORIGINAL SHA-256
    // =========================================

    if (!sendString(
            clientSocket,
            originalHash))
    {
        cout << "Failed to send SHA-256!"
             << endl;

        closesocket(clientSocket);

        WSACleanup();

        return 1;
    }

    cout << "SHA-256 sent to server."
         << endl;


    // =========================================
    // CLEANUP
    // =========================================

    closesocket(clientSocket);

    WSACleanup();

    return 0;
}