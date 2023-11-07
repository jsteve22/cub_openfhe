
#define PROFILE

#include <iostream>

#include "openfhe.h"

using namespace lbcrypto;

int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // benchmarking variables
    TimeVar t;
    double processingTime(0.0);

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(536903681);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetMaxRelinSkDeg(3);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning key generation (used for source data)..." << std::endl;

    TIC(t);

    keyPair = cryptoContext->KeyGen();

    processingTime = TOC(t);
    std::cout << "Key generation time: " << processingTime << "ms" << std::endl;

    if (!keyPair.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    std::cout << "Running key generation for homomorphic multiplication "
                 "evaluation keys..."
              << std::endl;

    TIC(t);

    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    processingTime = TOC(t);
    std::cout << "Key generation time for homomorphic multiplication evaluation keys: " << processingTime << "ms"
              << std::endl;

    // cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
    std::vector<int64_t> vectorOfInts2 = {1, 2, 3, 4, 5};
    // for (unsigned int i = 1; i < cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2; i++) {
    //         vectorOfInts2.push_back(0);
    // }
    Plaintext plaintext2               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning encryption of all plaintexts... ";

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;

    TIC(t);

    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext1));

    processingTime = TOC(t);

    std::cout << "Completed\n";

    std::cout << "\nAverage encryption time: " << processingTime << "ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 2 ciphertexts
    ////////////////////////////////////////////////////////////
    
    ciphertexts.push_back(cryptoContext->EvalMultMutable(ciphertexts[0], plaintext2));

    Plaintext plaintextDecMult;
    Plaintext plaintextDecMult2;

    TIC(t);

    cryptoContext->Decrypt(keyPair.secretKey, ciphertexts[0], &plaintextDecMult);
    cryptoContext->Decrypt(keyPair.secretKey, ciphertexts[1], &plaintextDecMult2);

    processingTime = TOC(t);
    std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;

    plaintextDecMult->SetLength(plaintext1->GetLength());

    std::cout << "\nResult of decryption of ciphertexts #1: \n";
    std::cout << plaintextDecMult << std::endl;
    std::cout << "\nResult of decryption of ciphertexts #2: \n";
    std::cout << plaintextDecMult2 << std::endl;

    return 0;
}
