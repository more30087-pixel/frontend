#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <string>
#include <vector>
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
// BRIDGE HTTP SERVER CONFIGURATION
// =========================================

const int BRIDGE_PORT = 9090;
const string SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 8080;


// =========================================
// SEND ALL (TCP)
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
// RECEIVE ALL (TCP)
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
// SEND STRING (TCP WIRE PROTOCOL)
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
// RECEIVE STRING (TCP WIRE PROTOCOL)
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
// SEND UINT64 (TCP WIRE PROTOCOL)
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
// CALCULATE SHA-256 OF STRING
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
// BYTES TO HEX STRING
// =========================================

string bytesToHex(
    const BYTE* data,
    int length)
{
    stringstream ss;

    for (int i = 0; i < length; i++)
    {
        ss << hex
           << setw(2)
           << setfill('0')
           << (int)data[i];
    }

    return ss.str();
}


// =========================================
// GET FILE SIZE
// =========================================

uint64_t getFileSize(
    const string& fileName)
{
    ifstream file(
        fileName,
        ios::binary | ios::ate
    );

    if (!file)
    {
        return 0;
    }

    uint64_t size =
        (uint64_t)file.tellg();

    file.close();

    return size;
}


// =========================================
// HTTP REQUEST STRUCTURE
// =========================================

struct HttpRequest
{
    string method;
    string path;
    string httpVersion;
    string contentType;
    string xUsername;
    string xPassword;
    string xFilename;
    int contentLength;
    string body;

    HttpRequest()
    {
        contentLength = 0;
    }
};


// =========================================
// PARSE HTTP REQUEST
// =========================================

bool parseHttpRequest(
    SOCKET clientSocket,
    HttpRequest& request)
{
    // Read the entire HTTP header
    // by reading until we find \r\n\r\n

    string rawData;
    char ch;
    bool headerComplete = false;

    while (!headerComplete)
    {
        int result = recv(
            clientSocket,
            &ch,
            1,
            0
        );

        if (result <= 0)
        {
            return false;
        }

        rawData += ch;

        // Check for end of headers
        if (rawData.length() >= 4)
        {
            string tail =
                rawData.substr(
                    rawData.length() - 4
                );

            if (tail == "\r\n\r\n")
            {
                headerComplete = true;
            }
        }
    }

    // Parse request line
    size_t firstLine =
        rawData.find("\r\n");

    if (firstLine == string::npos)
    {
        return false;
    }

    string requestLine =
        rawData.substr(0, firstLine);

    // Split request line into
    // METHOD PATH VERSION

    size_t space1 =
        requestLine.find(' ');

    if (space1 == string::npos)
    {
        return false;
    }

    request.method =
        requestLine.substr(0, space1);

    size_t space2 =
        requestLine.find(' ', space1 + 1);

    if (space2 == string::npos)
    {
        return false;
    }

    request.path =
        requestLine.substr(
            space1 + 1,
            space2 - space1 - 1
        );

    request.httpVersion =
        requestLine.substr(space2 + 1);

    // Parse headers
    string headers =
        rawData.substr(firstLine + 2);

    // Parse each header line
    size_t pos = 0;

    while (pos < headers.length())
    {
        size_t lineEnd =
            headers.find("\r\n", pos);

        if (lineEnd == string::npos)
        {
            break;
        }

        string line =
            headers.substr(
                pos,
                lineEnd - pos
            );

        if (line.empty())
        {
            break;
        }

        // Find the colon separator
        size_t colon =
            line.find(':');

        if (colon != string::npos)
        {
            string headerName =
                line.substr(0, colon);

            string headerValue =
                line.substr(colon + 1);

            // Trim leading whitespace
            // from the value
            size_t start =
                headerValue.find_first_not_of(' ');

            if (start != string::npos)
            {
                headerValue =
                    headerValue.substr(start);
            }

            // Convert header name to
            // lowercase for comparison
            string lowerName = headerName;

            for (size_t i = 0;
                 i < lowerName.length();
                 i++)
            {
                lowerName[i] =
                    tolower(lowerName[i]);
            }

            if (lowerName == "content-length")
            {
                request.contentLength =
                    atoi(headerValue.c_str());
            }
            else if (lowerName == "content-type")
            {
                request.contentType =
                    headerValue;
            }
            else if (lowerName == "x-username")
            {
                request.xUsername =
                    headerValue;
            }
            else if (lowerName == "x-password")
            {
                request.xPassword =
                    headerValue;
            }
            else if (lowerName == "x-filename")
            {
                request.xFilename =
                    headerValue;
            }
        }

        pos = lineEnd + 2;
    }

    // Read body if Content-Length > 0
    if (request.contentLength > 0)
    {
        vector<char> bodyBuffer(
            request.contentLength
        );

        int totalRead = 0;

        while (totalRead <
               request.contentLength)
        {
            int result = recv(
                clientSocket,
                bodyBuffer.data() + totalRead,
                request.contentLength - totalRead,
                0
            );

            if (result <= 0)
            {
                return false;
            }

            totalRead += result;
        }

        request.body = string(
            bodyBuffer.data(),
            request.contentLength
        );
    }

    return true;
}


// =========================================
// EXTRACT JSON STRING VALUE
// =========================================

string extractJsonValue(
    const string& json,
    const string& key)
{
    // Look for "key":"value" pattern
    string searchKey =
        "\"" + key + "\"";

    size_t keyPos =
        json.find(searchKey);

    if (keyPos == string::npos)
    {
        return "";
    }

    // Find the colon after the key
    size_t colonPos =
        json.find(':', keyPos + searchKey.length());

    if (colonPos == string::npos)
    {
        return "";
    }

    // Find the opening quote of the value
    size_t openQuote =
        json.find('"', colonPos + 1);

    if (openQuote == string::npos)
    {
        return "";
    }

    // Find the closing quote of the value
    size_t closeQuote =
        json.find('"', openQuote + 1);

    if (closeQuote == string::npos)
    {
        return "";
    }

    return json.substr(
        openQuote + 1,
        closeQuote - openQuote - 1
    );
}


// =========================================
// SEND HTTP RESPONSE
// =========================================

void sendHttpResponse(
    SOCKET clientSocket,
    int statusCode,
    const string& statusText,
    const string& contentType,
    const string& body)
{
    stringstream response;

    response << "HTTP/1.1 "
             << statusCode
             << " "
             << statusText
             << "\r\n";

    response << "Content-Type: "
             << contentType
             << "\r\n";

    response << "Access-Control-Allow-Origin: *"
             << "\r\n";

    response << "Access-Control-Allow-Methods: "
             << "GET, POST, OPTIONS"
             << "\r\n";

    response << "Access-Control-Allow-Headers: "
             << "Content-Type, X-Username, "
             << "X-Password, X-Filename"
             << "\r\n";

    response << "Connection: close"
             << "\r\n";

    response << "Content-Length: "
             << body.length()
             << "\r\n";

    response << "\r\n";

    response << body;

    string responseStr =
        response.str();

    sendAll(
        clientSocket,
        responseStr.c_str(),
        (int)responseStr.length()
    );
}


// =========================================
// SEND CORS PREFLIGHT RESPONSE
// =========================================

void sendCorsPreflightResponse(
    SOCKET clientSocket)
{
    string response =
        "HTTP/1.1 204 No Content\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: "
        "GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: "
        "Content-Type, X-Username, "
        "X-Password, X-Filename\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

    sendAll(
        clientSocket,
        response.c_str(),
        (int)response.length()
    );
}


// =========================================
// SERVE STATIC FILE
// =========================================

void serveStaticFile(
    SOCKET clientSocket,
    const string& fileName,
    const string& contentType)
{
    ifstream file(
        fileName,
        ios::binary
    );

    if (!file)
    {
        cout << "  File not found: "
             << fileName
             << endl;

        string body =
            "<!DOCTYPE html><html><body>"
            "<h1>404 Not Found</h1>"
            "</body></html>";

        sendHttpResponse(
            clientSocket,
            404,
            "Not Found",
            "text/html; charset=utf-8",
            body
        );

        return;
    }

    // Read entire file
    stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    string body = buffer.str();

    cout << "  Serving: "
         << fileName
         << " ("
         << body.length()
         << " bytes)"
         << endl;

    sendHttpResponse(
        clientSocket,
        200,
        "OK",
        contentType,
        body
    );
}


// =========================================
// HANDLE LOGIN REQUEST
// =========================================

void handleLogin(
    SOCKET clientSocket,
    const HttpRequest& request)
{
    cout << "  Processing login request..."
         << endl;

    // Parse JSON body to extract
    // username and password
    string username =
        extractJsonValue(
            request.body,
            "username"
        );

    string password =
        extractJsonValue(
            request.body,
            "password"
        );

    cout << "  Username: "
         << username
         << endl;

    // Validate credentials
    if (username == "admin" &&
        password == "12345")
    {
        cout << "  Login successful!"
             << endl;

        string responseBody =
            "{\"success\":true,"
            "\"message\":\"Credentials verified."
            " Ready for file transfer.\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );
    }
    else
    {
        cout << "  Login failed!"
             << endl;

        string responseBody =
            "{\"success\":false,"
            "\"message\":\"Invalid username"
            " or password.\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );
    }
}


// =========================================
// HANDLE FILE TRANSFER REQUEST
// =========================================

void handleTransfer(
    SOCKET clientSocket,
    const HttpRequest& request)
{
    cout << "  Processing transfer request..."
         << endl;

    string username = request.xUsername;
    string password = request.xPassword;
    string filename = request.xFilename;

    cout << "  Username: " << username << endl;
    cout << "  Filename: " << filename << endl;
    cout << "  File size: "
         << request.body.length()
         << " bytes" << endl;


    // =========================================
    // SAVE UPLOADED FILE TO TEMP
    // =========================================

    string tempFile = "upload_temp.bin";

    ofstream tempOutput(
        tempFile,
        ios::binary
    );

    if (!tempOutput)
    {
        cout << "  Failed to create temp file!"
             << endl;

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Could not create "
            "temporary file\","
            "\"failedStep\":\"preparation\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    tempOutput.write(
        request.body.c_str(),
        request.body.length()
    );

    tempOutput.close();

    uint64_t originalSize =
        (uint64_t)request.body.length();

    cout << "  Temp file saved: "
         << tempFile
         << endl;


    // =========================================
    // CALCULATE ORIGINAL FILE SHA-256
    // =========================================

    string originalHash;

    if (!calculateSHA256(
            tempFile,
            originalHash))
    {
        cout << "  SHA-256 calculation failed!"
             << endl;

        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"SHA-256 calculation "
            "failed\","
            "\"failedStep\":\"hashing\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  Original SHA-256: "
         << originalHash
         << endl;


    // =========================================
    // CONNECT TO SERVER.CPP VIA TCP
    // =========================================

    SOCKET serverSocket =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (serverSocket == INVALID_SOCKET)
    {
        cout << "  Socket creation failed!"
             << endl;

        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Could not create "
            "TCP socket\","
            "\"failedStep\":\"connection\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    sockaddr_in serverAddress;

    serverAddress.sin_family =
        AF_INET;

    serverAddress.sin_addr.s_addr =
        inet_addr(SERVER_IP.c_str());

    serverAddress.sin_port =
        htons(SERVER_PORT);

    cout << "  Connecting to server at "
         << SERVER_IP
         << ":"
         << SERVER_PORT
         << "..."
         << endl;

    if (connect(
            serverSocket,
            (sockaddr*)&serverAddress,
            sizeof(serverAddress)
        ) == SOCKET_ERROR)
    {
        cout << "  Connection to server failed!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Could not connect "
            "to server\","
            "\"failedStep\":\"connection\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  Connected to server!"
         << endl;


    // =========================================
    // SEND USERNAME
    // =========================================

    if (!sendString(
            serverSocket,
            username))
    {
        cout << "  Failed to send username!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to send "
            "username to server\","
            "\"failedStep\":\"authentication\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  Username sent to server."
         << endl;


    // =========================================
    // RECEIVE 32-BYTE CHALLENGE
    // =========================================

    BYTE challenge[32];

    if (!recvAll(
            serverSocket,
            (char*)challenge,
            32))
    {
        cout << "  Failed to receive challenge!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to receive "
            "authentication challenge. "
            "Username may be invalid.\","
            "\"failedStep\":\"authentication\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  Authentication challenge received."
         << endl;


    // =========================================
    // COMPUTE & SEND AUTH HASH
    // =========================================

    string authHash;

    if (!createAuthenticationHash(
            password,
            challenge,
            authHash))
    {
        cout << "  Auth hash creation failed!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to create "
            "authentication hash\","
            "\"failedStep\":\"authentication\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    if (!sendString(
            serverSocket,
            authHash))
    {
        cout << "  Failed to send auth hash!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to send "
            "authentication response\","
            "\"failedStep\":\"authentication\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  Authentication hash sent."
         << endl;


    // =========================================
    // RECEIVE AUTH RESULT
    // =========================================

    string authResult;

    if (!receiveString(
            serverSocket,
            authResult))
    {
        cout << "  Failed to receive auth result!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to receive "
            "authentication result\","
            "\"failedStep\":\"authentication\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  Server auth response: "
         << authResult
         << endl;

    if (authResult != "AUTH_SUCCESS")
    {
        cout << "  Authentication failed!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Authentication failed."
            " Invalid credentials.\","
            "\"failedStep\":\"authentication\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  Authentication successful!"
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
        cout << "  Crypto provider failed!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Cryptographic provider "
            "initialization failed\","
            "\"failedStep\":\"encryption\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }


    // =========================================
    // CREATE AES KEY
    // =========================================

    HCRYPTKEY hKey = 0;

    if (!createAESKey(
            hProv,
            hKey))
    {
        cout << "  AES key creation failed!"
             << endl;

        CryptReleaseContext(hProv, 0);
        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"AES key creation "
            "failed\","
            "\"failedStep\":\"encryption\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  AES-256 key created."
         << endl;


    // =========================================
    // GENERATE RANDOM IV
    // =========================================

    BYTE iv[16];

    if (!generateIV(
            hProv,
            iv))
    {
        cout << "  IV generation failed!"
             << endl;

        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"IV generation "
            "failed\","
            "\"failedStep\":\"encryption\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    string ivHex =
        bytesToHex(iv, 16);

    cout << "  Random IV generated: "
         << ivHex
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
        cout << "  Failed to set AES IV!"
             << endl;

        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to set "
            "AES IV\","
            "\"failedStep\":\"encryption\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  AES IV set successfully."
         << endl;


    // =========================================
    // ENCRYPT FILE
    // =========================================

    string encryptedFile =
        "bridge_encrypted.bin";

    cout << "  Encrypting file..."
         << endl;

    if (!encryptFile(
            tempFile,
            encryptedFile,
            hKey))
    {
        cout << "  File encryption failed!"
             << endl;

        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        closesocket(serverSocket);
        remove(tempFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"File encryption "
            "failed\","
            "\"failedStep\":\"encryption\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  File encrypted successfully!"
         << endl;


    // =========================================
    // CLOSE AES KEY & CRYPTO PROVIDER
    // =========================================

    CryptDestroyKey(hKey);

    CryptReleaseContext(
        hProv,
        0);


    // =========================================
    // GET ENCRYPTED FILE SIZE
    // =========================================

    uint64_t encryptedSize =
        getFileSize(encryptedFile);

    cout << "  Encrypted file size: "
         << encryptedSize
         << " bytes"
         << endl;


    // =========================================
    // SEND FILENAME TO SERVER
    // =========================================

    if (!sendString(
            serverSocket,
            filename))
    {
        cout << "  Failed to send filename!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());
        remove(encryptedFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to send "
            "filename to server\","
            "\"failedStep\":\"transfer\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  Filename sent to server."
         << endl;


    // =========================================
    // SEND AES IV TO SERVER
    // =========================================

    if (!sendAll(
            serverSocket,
            (char*)iv,
            16))
    {
        cout << "  Failed to send IV!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());
        remove(encryptedFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to send "
            "AES IV to server\","
            "\"failedStep\":\"transfer\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  AES IV sent to server."
         << endl;


    // =========================================
    // SEND ENCRYPTED FILE SIZE
    // =========================================

    if (!sendUint64(
            serverSocket,
            encryptedSize))
    {
        cout << "  Failed to send file size!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());
        remove(encryptedFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to send "
            "encrypted file size\","
            "\"failedStep\":\"transfer\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  Encrypted file size sent."
         << endl;


    // =========================================
    // SEND ENCRYPTED DATA IN 4KB CHUNKS
    // =========================================

    ifstream encryptedInput(
        encryptedFile,
        ios::binary
    );

    if (!encryptedInput)
    {
        cout << "  Could not open encrypted file!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());
        remove(encryptedFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Could not open "
            "encrypted file\","
            "\"failedStep\":\"transfer\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    char sendBuffer[4096];
    uint64_t totalSent = 0;

    while (
        encryptedInput.read(
            sendBuffer,
            sizeof(sendBuffer))
        ||
        encryptedInput.gcount() > 0)
    {
        int bytesRead =
            (int)encryptedInput.gcount();

        if (!sendAll(
                serverSocket,
                sendBuffer,
                bytesRead))
        {
            cout << "  Encrypted data transfer failed!"
                 << endl;

            encryptedInput.close();
            closesocket(serverSocket);
            remove(tempFile.c_str());
            remove(encryptedFile.c_str());

            string responseBody =
                "{\"success\":false,"
                "\"error\":\"Encrypted data "
                "transfer failed\","
                "\"failedStep\":\"transfer\"}";

            sendHttpResponse(
                clientSocket,
                200,
                "OK",
                "application/json",
                responseBody
            );

            return;
        }

        totalSent += bytesRead;

        cout << "\r  Encrypted data sent: "
             << totalSent
             << " / "
             << encryptedSize
             << " bytes"
             << flush;
    }

    cout << endl;

    encryptedInput.close();

    cout << "  Encrypted file transferred!"
         << endl;


    // =========================================
    // SEND ORIGINAL SHA-256 HASH
    // =========================================

    if (!sendString(
            serverSocket,
            originalHash))
    {
        cout << "  Failed to send SHA-256!"
             << endl;

        closesocket(serverSocket);
        remove(tempFile.c_str());
        remove(encryptedFile.c_str());

        string responseBody =
            "{\"success\":false,"
            "\"error\":\"Failed to send "
            "SHA-256 hash\","
            "\"failedStep\":\"integrity\"}";

        sendHttpResponse(
            clientSocket,
            200,
            "OK",
            "application/json",
            responseBody
        );

        return;
    }

    cout << "  SHA-256 hash sent to server."
         << endl;


    // =========================================
    // CLOSE TCP CONNECTION TO SERVER
    // =========================================

    closesocket(serverSocket);

    cout << "  TCP connection closed."
         << endl;


    // =========================================
    // CLEANUP TEMP FILES
    // =========================================

    remove(tempFile.c_str());
    remove(encryptedFile.c_str());

    cout << "  Temp files cleaned up."
         << endl;


    // =========================================
    // SEND SUCCESS RESPONSE
    // =========================================

    stringstream jsonResponse;

    jsonResponse << "{"
        << "\"success\":true,"
        << "\"connection\":{"
            << "\"success\":true,"
            << "\"server\":\"" << SERVER_IP << "\","
            << "\"port\":" << SERVER_PORT
        << "},"
        << "\"authentication\":{"
            << "\"success\":true,"
            << "\"method\":\"SHA-256 Challenge-Response\""
        << "},"
        << "\"encryption\":{"
            << "\"success\":true,"
            << "\"algorithm\":\"AES-256-CBC\","
            << "\"ivHex\":\"" << ivHex << "\","
            << "\"originalSize\":" << originalSize << ","
            << "\"encryptedSize\":" << encryptedSize
        << "},"
        << "\"transfer\":{"
            << "\"success\":true,"
            << "\"bytesSent\":" << totalSent
        << "},"
        << "\"integrity\":{"
            << "\"originalHash\":\"" << originalHash << "\","
            << "\"hashSentToServer\":true"
        << "}"
        << "}";

    string responseBody =
        jsonResponse.str();

    cout << "  Transfer complete! Sending response."
         << endl;

    sendHttpResponse(
        clientSocket,
        200,
        "OK",
        "application/json",
        responseBody
    );
}


// =========================================
// MAIN
// =========================================

int main()
{
    cout << "=========================================="
         << endl;
    cout << "  BRIDGE HTTP SERVER"
         << endl;
    cout << "  Browser <-> Bridge <-> Server"
         << endl;
    cout << "=========================================="
         << endl;
    cout << endl;


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
    // CREATE HTTP SERVER SOCKET
    // =========================================

    SOCKET httpSocket =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (httpSocket == INVALID_SOCKET)
    {
        cout << "Socket creation failed!"
             << endl;

        WSACleanup();

        return 1;
    }

    cout << "HTTP server socket created!"
         << endl;


    // =========================================
    // ALLOW PORT REUSE
    // =========================================

    int optval = 1;

    setsockopt(
        httpSocket,
        SOL_SOCKET,
        SO_REUSEADDR,
        (char*)&optval,
        sizeof(optval)
    );


    // =========================================
    // BIND TO PORT 9090
    // =========================================

    sockaddr_in bridgeAddress;

    bridgeAddress.sin_family =
        AF_INET;

    bridgeAddress.sin_addr.s_addr =
        INADDR_ANY;

    bridgeAddress.sin_port =
        htons(BRIDGE_PORT);

    if (bind(
            httpSocket,
            (sockaddr*)&bridgeAddress,
            sizeof(bridgeAddress)
        ) == SOCKET_ERROR)
    {
        cout << "Bind failed! Port "
             << BRIDGE_PORT
             << " may be in use."
             << endl;

        closesocket(httpSocket);

        WSACleanup();

        return 1;
    }

    cout << "Bridge bound to port "
         << BRIDGE_PORT
         << endl;


    // =========================================
    // LISTEN FOR HTTP CONNECTIONS
    // =========================================

    if (listen(
            httpSocket,
            5
        ) == SOCKET_ERROR)
    {
        cout << "Listen failed!"
             << endl;

        closesocket(httpSocket);

        WSACleanup();

        return 1;
    }

    cout << endl;
    cout << "=========================================="
         << endl;
    cout << "  Bridge is running on"
         << " http://127.0.0.1:"
         << BRIDGE_PORT
         << endl;
    cout << "  Open this URL in your browser"
         << endl;
    cout << "=========================================="
         << endl;
    cout << endl;


    // =========================================
    // MAIN HTTP REQUEST LOOP
    // =========================================

    while (true)
    {
        // =========================================
        // ACCEPT HTTP CONNECTION
        // =========================================

        sockaddr_in httpClientAddress;

        int httpClientAddressSize =
            sizeof(httpClientAddress);

        SOCKET httpClientSocket =
            accept(
                httpSocket,
                (sockaddr*)&httpClientAddress,
                &httpClientAddressSize
            );

        if (httpClientSocket == INVALID_SOCKET)
        {
            cout << "Accept failed!"
                 << endl;

            continue;
        }

        cout << "------------------------------------"
             << endl;
        cout << "New HTTP connection accepted."
             << endl;


        // =========================================
        // PARSE HTTP REQUEST
        // =========================================

        HttpRequest request;

        if (!parseHttpRequest(
                httpClientSocket,
                request))
        {
            cout << "  Failed to parse HTTP request!"
                 << endl;

            closesocket(httpClientSocket);

            continue;
        }

        cout << "  "
             << request.method
             << " "
             << request.path
             << endl;


        // =========================================
        // ROUTE TO HANDLER
        // =========================================

        if (request.method == "OPTIONS")
        {
            // CORS preflight response
            cout << "  CORS preflight response."
                 << endl;

            sendCorsPreflightResponse(
                httpClientSocket
            );
        }
        else if (request.method == "GET" &&
                 (request.path == "/" ||
                  request.path == "/index.html"))
        {
            serveStaticFile(
                httpClientSocket,
                "index.html",
                "text/html; charset=utf-8"
            );
        }
        else if (request.method == "GET" &&
                 request.path == "/styles.css")
        {
            serveStaticFile(
                httpClientSocket,
                "styles.css",
                "text/css; charset=utf-8"
            );
        }
        else if (request.method == "GET" &&
                 request.path == "/app.js")
        {
            serveStaticFile(
                httpClientSocket,
                "app.js",
                "application/javascript; charset=utf-8"
            );
        }
        else if (request.method == "POST" &&
                 request.path == "/api/login")
        {
            handleLogin(
                httpClientSocket,
                request
            );
        }
        else if (request.method == "POST" &&
                 request.path == "/api/transfer")
        {
            handleTransfer(
                httpClientSocket,
                request
            );
        }
        else
        {
            // Unknown route
            cout << "  404 - Route not found."
                 << endl;

            string body =
                "{\"success\":false,"
                "\"error\":\"Route not found\"}";

            sendHttpResponse(
                httpClientSocket,
                404,
                "Not Found",
                "application/json",
                body
            );
        }


        // =========================================
        // CLOSE HTTP CONNECTION
        // =========================================

        closesocket(httpClientSocket);

        cout << "  Connection closed."
             << endl;
        cout << endl;
    }


    // =========================================
    // CLEANUP (unreachable in normal use)
    // =========================================

    closesocket(httpSocket);

    WSACleanup();

    return 0;
}
