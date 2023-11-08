
#define PROFILE

#include <iostream>

#include "openfhe.h"

using namespace lbcrypto;

void EvalNoiseBFV(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, Plaintext ptxt, usint ptm,
                  double& noise, double& logQ);

int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // benchmarking variables
    TimeVar t;
    double processingTime(0.0);

    usint ptm = 536903681;

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
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

    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1});

    processingTime = TOC(t);
    std::cout << "Key generation time for homomorphic multiplication evaluation keys: " << processingTime << "ms"
              << std::endl;

    // cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 100};
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

    std::cout << std::endl;
    double noise, logQ;

    EvalNoiseBFV(keyPair.secretKey, ciphertexts[0], plaintext2, ptm, noise, logQ);
    EvalNoiseBFV(keyPair.secretKey, ciphertexts[1], plaintext2, ptm, noise, logQ);

    auto rotated_ciphertext = cryptoContext->EvalRotate(ciphertexts[0], 1);
    EvalNoiseBFV(keyPair.secretKey, rotated_ciphertext, plaintext2, ptm, noise, logQ);

    return 0;
}

void EvalNoiseBFV(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, Plaintext ptxt, usint ptm,
                  double& noise, double& logQ) {
    const auto cryptoParams = std::static_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    DCRTPoly s                      = privateKey->GetPrivateElement();

    size_t sizeQl = cv[0].GetParams()->GetParams().size();
    size_t sizeQs = s.GetParams()->GetParams().size();

    size_t diffQl = sizeQs - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    DCRTPoly sPower(scopy);

    DCRTPoly b = cv[0];
    b.SetFormat(Format::EVALUATION);

    DCRTPoly ci;
    for (size_t i = 1; i < cv.size(); i++) {
        ci = cv[i];
        ci.SetFormat(Format::EVALUATION);

        b += sPower * ci;
        sPower *= scopy;
    }

    const auto encParams                = cryptoParams->GetElementParams();
    NativeInteger NegQModt              = cryptoParams->GetNegQModt();
    NativeInteger NegQModtPrecon        = cryptoParams->GetNegQModtPrecon();
    const NativeInteger t               = cryptoParams->GetPlaintextModulus();
    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();

    DCRTPoly plain = ptxt->GetElement<DCRTPoly>();
    plain.SetFormat(Format::COEFFICIENT);
    plain.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
    plain.SetFormat(Format::EVALUATION);
    DCRTPoly res;
    res = b - plain;

    // Converts back to coefficient representation
    res.SetFormat(Format::COEFFICIENT);
    size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
    noise        = (log2(res.Norm()));

    logQ = 0;
    for (usint i = 0; i < sizeQ; i++) {
        double logqi = log2(cryptoParams->GetElementParams()->GetParams()[i]->GetModulus().ConvertToInt());
        logQ += logqi;
    }

    std::cout << "logQ: " << logQ << std::endl;
    std::cout << "noise: " << noise << std::endl;
}
