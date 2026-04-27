#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <cstring>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// ── Archive format ────────────────────────────────────────────────────────────
//
// Plaintext block (encrypted as a whole):
//   [4B] entry count N
//   For each entry:
//     [2B] total size
//     [1B] name length
//     [website bytes]
//     [1B] number of entry
//     For each entry : 
//         [1B] username length
//         [username bytes]
//         [1B] password length
//         [password bytes]
//
// On-disk file:
//   Magic   : "KRG1" (4 bytes)
//   Salt    : 16 bytes
//   IV+tag+ciphertext (rest of file)


namespace fs = std::filesystem;

int index;



struct entry{
    std::string username;
    std::string password;
};

struct indexble {
    int size;
    std::string name;
    std::vector<entry> values;
};

struct comp_index{
    std::vector<indexble> RL_INDEX;
    uint16_t count;
};

struct GetSec {
    std::vector<BYTE> salt;
    std::vector<BYTE> IV;
    std::vector<BYTE> TAG;
    std::vector<BYTE> key;
};

GetSec LSMP;
comp_index LMPP;

std::string path;

static bool deriveKey(const std::string& password, const BYTE* salt, DWORD saltLen, BYTE* keyOut, DWORD keyLen, DWORD iterations = 100000){
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)) return false;

    bool ok = !BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password.data(), (ULONG)password.size(), (PUCHAR)salt, saltLen, iterations, keyOut, keyLen, 0);

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// Encrypt plaintext with AES-256-GCM.
// Output layout: [12-byte IV][16-byte tag][ciphertext]

void print_lst(){
    int ze=0;
    std::cout << "_________________________________________________________________________________" << std::endl << "Saved Note Index :";
    for (auto& e : LMPP.RL_INDEX){
        std::string website = e.name;
        int account_size = e.values.size();
        std::cout << "[" << ze << "] "<<"website : " << website << ", user: " << account_size << std::endl;
        ze++;
    }
    std::cout << "_________________________________________________________________________________" << std::endl;


}

bool LD_SEC(const std::string& archivePath) {

    std::string password;
    std::getline(std::cin, password);

    std::ifstream in(archivePath, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open archive.\n";
        return false;
    }

    // Magic
    char magic[4];
    in.read(magic, 4);
    if (in.gcount() != 4 || memcmp(magic, "KRG1", 4) != 0) {
        std::cerr << "Not a valid KRG1 archive.\n";
        return false;
    }

    // Salt (16 bytes)
    in.read(reinterpret_cast<char*>(LSMP.salt.data()), 16);
    if (in.gcount() != 16) return false;

    // Derive key
    if (!deriveKey(password, LSMP.salt.data(), 16, LSMP.key.data(), 32)) {
        std::cerr << "Key derivation failed\n";
        return false;
    }

    // IV (12 bytes)
    in.read(reinterpret_cast<char*>(LSMP.IV.data()), 12);
    if (in.gcount() != 12) return false;

    // TAG (16 bytes)
    in.read(reinterpret_cast<char*>(LSMP.TAG.data()), 16);
    if (in.gcount() != 16) return false;

    // Read remaining encrypted data
    std::vector<BYTE> enc(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>()
    );

    if (enc.empty()) {
        std::cerr << "No encrypted data.\n";
        return false;
    }

    // TODO: decrypt here
    // aesgcmDecrypt(...)

    return true;
}



static bool aesgcmEncrypt(const BYTE* key, const std::vector<BYTE>& plain, std::vector<BYTE>& out){
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)) return false;

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Random 12-byte IV
    BYTE iv[12];
    BCryptGenRandom(nullptr, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    BYTE tag[16] = {};
    authInfo.pbNonce    = iv;
    authInfo.cbNonce    = sizeof(iv);
    authInfo.pbTag      = tag;
    authInfo.cbTag      = sizeof(tag);

    DWORD cbResult = 0;
    ULONG cipherLen = (ULONG)plain.size();
    std::vector<BYTE> cipher(cipherLen);

    NTSTATUS st = BCryptEncrypt(hKey, (PUCHAR)plain.data(), (ULONG)plain.size(),  &authInfo, nullptr, 0, cipher.data(), cipherLen, &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (st) return false;

    // Pack: IV | tag | ciphertext
    out.insert(out.end(), iv,      iv + sizeof(iv));
    out.insert(out.end(), tag,     tag + sizeof(tag));
    out.insert(out.end(), cipher.begin(), cipher.end());
    return true;
}

// Decrypt AES-256-GCM.  Input layout: [12B IV][16B tag][ciphertext]
static bool aesgcmDecrypt(const BYTE* key, const std::vector<BYTE>& blob, std::vector<BYTE>& plain){
    if (blob.size() < 28) return false; // IV + tag minimum

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)) return false;

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    const BYTE* iv      = blob.data();
    const BYTE* tag     = blob.data() + 12;
    const BYTE* cipher  = blob.data() + 28;
    ULONG  cipherLen    = (ULONG)(blob.size() - 28);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    BYTE tagCopy[16];
    memcpy(tagCopy, tag, 16);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = 12;
    authInfo.pbTag   = tagCopy;
    authInfo.cbTag   = 16;

    plain.resize(cipherLen);
    DWORD cbResult = 0;
    NTSTATUS st = BCryptDecrypt(hKey,
        (PUCHAR)cipher, cipherLen,
        &authInfo,
        nullptr, 0,
        plain.data(), cipherLen,
        &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (st) { plain.clear(); return false; } // tag mismatch → wrong password
    plain.resize(cbResult);
    return true;
}

bool save_all(){
    LMPP.count=LMPP.RL_INDEX.size();
    std::string p1, p2;

    std::cout << "Enter new password: ";
    std::getline(std::cin, p1);

    std::cout << "Confirm password: ";
    std::getline(std::cin, p2);

    if (p1 != p2) {
        std::cerr << "Passwords do not match\n";
        return false;
    }
    BCryptGenRandom(nullptr, LSMP.salt.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!deriveKey(p2, LSMP.salt.data(), 16, LSMP.key.data(), 32)) {
        std::cerr << "Key derivation failed\n";
        return false;
    }
    std::vector<BYTE> plain;
    plain.push_back(static_cast<BYTE>(LMPP.count & 0xFF));
    plain.push_back(static_cast<BYTE>((LMPP.count >> 8) &0xFF));
    plain.push_back(static_cast<BYTE>((LMPP.count >> 16) &0xFF));
    plain.push_back(static_cast<BYTE>((LMPP.count >> 24) &0xFF));
    for (auto& j: LMPP.RL_INDEX){
        plain.push_back(static_cast<BYTE>((j.name.size()) &0xFF));
        plain.insert(plain.end(), j.name.begin(), j.name.end());
        plain.push_back(static_cast<BYTE>((j.size) &0xFF));
        for (auto y: j.values){
            plain.push_back(static_cast<BYTE>((y.username.size()) &0xFF));
            plain.insert(plain.end(),y.username.begin(), y.username.end());
            plain.push_back(static_cast<BYTE>((y.password.size()) &0xFF));
            plain.insert(plain.end(), y.password.begin(), y.password.end());
        }
    }
    std::vector<BYTE> enc;
    if (aesgcmEncrypt(LSMP.key.data(), plain, enc)){
        std::vector<BYTE> file;
        std::string HEADer="KRG1";
        file.insert(file.begin(), HEADer.begin(), HEADer.end());
        file.insert(file.end(), LSMP.salt.begin(), LSMP.salt.end());
        file.insert(file.end(), enc.begin(), enc.end());
        std::ofstream outputFileStream(path, std::ios::out | std::ios::binary | std::ios::trunc);
        outputFileStream.write(reinterpret_cast<const char*>(file.data()), file.size());
        SecureZeroMemory(p1.data(), p1.size());
        SecureZeroMemory(p2.data(), p2.size());
        return true;
    }
    return false;
}


bool add_index(){
    std::cout << "new named website, name it:"<< std::endl;
    std::string new_named_entry;
    std::getline(std::cin, new_named_entry);
    std::cout << "username:"<< std::endl;
    std::string username;
    std::getline(std::cin, username);
    std::cout << "password :"<< std::endl;
    std::string password;
    std::getline(std::cin, password);
    entry timed;
    timed.password = password;
    timed.username = username;
    for (auto& e: LMPP.RL_INDEX){
        if (e.name==new_named_entry){
            if (e.size>0xFF){
                std::cout << "too much entries" << std::endl;
                return false;
            }
            e.size++;
            e.values.push_back(timed);
            return true;
        }
    }
    indexble ls;
    ls.name = new_named_entry;
    ls.size=1;
    ls.values.push_back(timed);
    LMPP.RL_INDEX.push_back(ls);
    std::cout << "entry saved correctly" << std::endl;
    return true;
}


static uint16_t readU16(const BYTE* p) { return p[0] | (p[1] << 8); }
static uint32_t readU32(const BYTE* p) {
    return p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
}




int use() {
    LSMP.salt.resize(16);
    LSMP.IV.resize(12);
    LSMP.TAG.resize(16);
    LSMP.key.resize(32);
    std::string srcPath;
    std::cout << "Source folder: ";
    std::getline(std::cin, srcPath);
    path = srcPath;
    if (!LD_SEC(srcPath)){
        std::cout << "got issue while loading security measures with LD_SEC" << std::endl;
    }
    std::ifstream in(srcPath, std::ios::binary);
    if (!in) { std::cerr << "Cannot open archive.\n"; return -76; }
    in.seekg(4 + 16); // skip magic + salt
    std::vector<BYTE> cipherBlob(std::istreambuf_iterator<char>(in), {});
    if ((cipherBlob.size()==28 )||(cipherBlob.size()== 0)){
        add_index();
        save_all();
        return 20;
    }
    else if (cipherBlob.size()<28)
    {
        std::cerr << "Corrupted archive (too small)\n" << cipherBlob.size() << std::endl;
        return -172;
    }
    
    in.close();
    std::vector<BYTE> plain;
    if (!aesgcmDecrypt(LSMP.key.data(), cipherBlob, plain)) {
        std::cerr << "Decryption failed — wrong password or corrupted archive.\n";
        SecureZeroMemory(LSMP.key.data(), LSMP.key.size());
        return -1;
    }
    SecureZeroMemory(LSMP.key.data(), LSMP.key.size());
    const BYTE* p   = plain.data();
    const BYTE* end = plain.data() + plain.size();

    if (p + 4 > end) { std::cerr << "Corrupt archive.\n"; return -2; }
    LMPP.count  = readU32(p); p += 4;
    LMPP.RL_INDEX.clear();
    LMPP.RL_INDEX.resize(LMPP.count);
    for (uint32_t i = 0; i < LMPP.count; i++) {
        if (p + 2 > end) { std::cerr << "Corrupt index.\n"; return -3; }
        uint8_t namlen = p[0]; p++;
        if (p + namlen > end) { std::cerr << "Corrupt index.\n"; return -4; }
        LMPP.RL_INDEX[i].name = std::string((char*)p, namlen); p += namlen;
        LMPP.RL_INDEX[i].size = p[0]; p++;
        
        for (int az=0; az<LMPP.RL_INDEX[i].size; az++){
            int usrlen = p[0]; p++;
            entry e;
            e.username=std::string((char*)p, usrlen);
            p+=usrlen;
            
            int passlen = p[0]; p++;
            e.password= std::string((char*)p, passlen);p+=passlen;
            LMPP.RL_INDEX[i].values.push_back(e);
        }
    }
    while (true) {
        print_lst();
        std::cout << "\nEnter index to read/modify (or 'q' to quit, 'a' to delete, 'x' for a new one): ";
        std::string input;
        std::getline(std::cin, input);

        if (input == "q" || input == "Q") break;
        else if (input == "x" || input == "X"){
            add_index();
            
        }
        else if (input == "a" || input == "A"){
            std::cout << "\nEnter index to delete (negative index for none): "<< std::endl;
            std::string newinput;
            std::getline(std::cin, newinput);
            int Id2 = std::stoi(newinput);
            if (Id2>=0){
                LMPP.RL_INDEX.erase(LMPP.RL_INDEX.begin()+Id2-1);
            }  
        }
        else {
            int Id = std::stoi(input);
            std::cout << "website selected" <<LMPP.RL_INDEX[Id].name << std::endl;
            int hjt=0;
            for (auto& slk: LMPP.RL_INDEX[Id].values){
                std::cout << "["<< hjt << "] "<<slk.username << std::endl;
                hjt++;
            }
            std::cout << "\nEnter index to get password (negative index for none): " << std::endl;
            std::string newinput;
            std::getline(std::cin, newinput);
            int Id2 = std::stoi(newinput);
            if (Id2>=0){
                std::cout << "password for username " << LMPP.RL_INDEX[Id].values[Id2].username << " : " << LMPP.RL_INDEX[Id].values[Id2].password << std::endl;
            }
        }
    }
    if (save_all()){
        std::cout << "saved correctly" << std::endl;
        return 1;
    }
    return -61;
}

bool open(){
    LSMP.salt.resize(16);
    BCryptGenRandom(nullptr, LSMP.salt.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::string filename;
    std::cout << "Filename : "<< std::endl;
    std::getline(std::cin, filename);
    std::vector<BYTE> out;
    std::string HEADer="KRG1";
    out.insert(out.begin(), HEADer.begin(), HEADer.end());
    out.insert(out.end(), LSMP.salt.begin(), LSMP.salt.end());
    std::ofstream outputFileStream(filename, std::ios::out | std::ios::binary | std::ios::trunc);
    outputFileStream.write(reinterpret_cast<const char*>(out.data()), out.size());
    return true;
}


int main(){
    
    while (true){
        std::string ind;
        std::cout << " choose between openning a file or creating one :\n [0] open an existing file \n [1] creat a new file \n [2] Quit"<< std::endl;
        std::getline(std::cin, ind);
        int mls = std::stoi(ind);
        if (mls==0){
            use();
        }
        else if (mls==1)
        {
            open();
        }
        else if (mls==2){
            break;
        }    
    }
    return 1;
}
