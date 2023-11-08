#include "openfhe.h"

#include <iostream>
#include <stdint.h>
#include <iomanip>

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<math.h>

using namespace std;
using namespace lbcrypto;

typedef uint64_t u64;
typedef int64_t  i64;

i64 mult = 0;
i64 add = 0;

enum LayerType {
  conv2d,
  dense,
  meanpooling,
  flatten
};

vector<u64> center_lift(Plaintext plaintext, u64 size, u64 modulus);

vector<vector<u64>> load_image(const char* filename, i64* channels, i64* width, i64* height);

void conv_layer(const char* filename, vector<vector<u64>> &input_layer, int padded, Encryptor &encryptor, Evaluator &evaluator, Decryptor &decryptor);
void pad_image(vector<u64> &image);
void pad_images(vector<vector<u64>> &images);

vector<vector<vector<u64>>> load_conv_weights(const char* filename);
void prepare_filter(vector<vector<vector<u64>>> &filter, u64 image_width);

void batch_filter(vector<vector<vector<u64>>> &filter, u64 image_size, u64 &filters_per_ciphertext);
vector<vector<u64>> unbatch_results(Plaintext plaintext, u64 image_size, u64 filters_per_ciphertext);

void reformat_image(vector<u64> &image, u64 size, u64 filter_size);
void scale_image(vector<u64> &image, u64 scale);
void ReLU_image(vector<u64> &image);

void mean_pooling(vector<vector<u64>> &image);

u64 PLAINTEXT_MOD = 1<<20;
u64 POLY_DEGREE = 1<<13;

int main() {
  srand((unsigned int)time(NULL));

  double start, end, running = 0;

  // u64 poly_degree = 1<<11;
  // u64 size = poly_degree;

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

  KeyPair<DCRTPoly> keyPair;

  keyPair = cryptoContext->KeyGen();

  if (!keyPair.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  // Generating Plaintexts
  // Plaintext plaintext1               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
  //
  // Encrypting plaintexts
  // Ciphertext<DCRTPoly> ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  //
  // Decrypting ciphertexts
  // cryptoContext->Decrypt(keyPair.secretKey, ciphertexts[0], &plaintextDecMult);
  //
  // Plaintext polynomial multiplication
  // Ciphertext<DCRTPoly> result = cryptoContext->EvalMultMutable(ciphertexts[0], plaintext2);

  i64 i, j, k;

  i64 channels, width, height;
  vector<vector<u64>> image = load_image("./test_image/cifar_image.txt", &channels, &width, &height);

  start = (double)clock()/CLOCKS_PER_SEC;
  conv_layer("./miniONN_cifar_model/conv2d.kernel.txt", image, 1, encryptor, evaluator, decryptor);
  end = (double)clock()/CLOCKS_PER_SEC;
  running += (end - start);

  channels = image.size();
  width = (i64)sqrt((double)image[0].size());
  cout << "channels after layer: " << channels << "\n";
  cout << "width after layer: " << width << "\n";

  for (u64 i = 0; i < image[0].size(); i++) {
    // fprintf(stdout, "%2ld ", image[0][i]);
    cout << setw(2) << (i64)image[0][i] << " ";
    if ( i % 15 == 14 )
      fprintf(stdout, "\n");
  }
  fprintf(stdout, "\n");
  cout << "\n\n\n";

  start = (double)clock()/CLOCKS_PER_SEC;
  conv_layer("./miniONN_cifar_model/conv2d_1.kernel.txt", image, 1, encryptor, evaluator, decryptor);
  end = (double)clock()/CLOCKS_PER_SEC;
  running += (end - start);

  mean_pooling(image);
  channels = image.size();
  width = (i64)sqrt((double)image[0].size());
  cout << "channels after layer: " << channels << "\n";
  cout << "width after layer: " << width << "\n";
  for (u64 i = 0; i < image[0].size(); i++) {
    // fprintf(stdout, "%2ld ", image[0][i]);
    cout << setw(2) << (i64)image[0][i] << " ";
    if ( i % 15 == 14 )
      fprintf(stdout, "\n");
  }
  fprintf(stdout, "\n");

  start = (double)clock()/CLOCKS_PER_SEC;
  conv_layer("./miniONN_cifar_model/conv2d_2.kernel.txt", image, 1, encryptor, evaluator, decryptor);
  end = (double)clock()/CLOCKS_PER_SEC;
  running += (end - start);
  fprintf(stdout, "Done conv2d_2\n");

  start = (double)clock()/CLOCKS_PER_SEC;
  conv_layer("./miniONN_cifar_model/conv2d_3.kernel.txt", image, 1, encryptor, evaluator, decryptor);
  end = (double)clock()/CLOCKS_PER_SEC;
  running += (end - start);
  fprintf(stdout, "Done conv2d_3\n");

  mean_pooling(image);

  start = (double)clock()/CLOCKS_PER_SEC;
  conv_layer("./miniONN_cifar_model/conv2d_4.kernel.txt", image, 1, encryptor, evaluator, decryptor);
  end = (double)clock()/CLOCKS_PER_SEC;
  running += (end - start);
  fprintf(stdout, "Done conv2d_4\n");

  start = (double)clock()/CLOCKS_PER_SEC;
  conv_layer("./miniONN_cifar_model/conv2d_5.kernel.txt", image, 0, encryptor, evaluator, decryptor);
  end = (double)clock()/CLOCKS_PER_SEC;
  running += (end - start);
  fprintf(stdout, "Done conv2d_5\n");

  start = (double)clock()/CLOCKS_PER_SEC;
  conv_layer("./miniONN_cifar_model/conv2d_6.kernel.txt", image, 0, encryptor, evaluator, decryptor);
  end = (double)clock()/CLOCKS_PER_SEC;
  running += (end - start);
  fprintf(stdout, "Done conv2d_6\n");

  channels = image.size();
  width = (i64)sqrt((double)image[0].size());
  cout << "channels after layer: " << channels << "\n";
  cout << "width after layer: " << width << "\n";
  for (u64 i = 0; i < image[0].size(); i++) {
    // fprintf(stdout, "%2ld ", image[0][i]);
    cout << setw(2) << (i64)image[0][i] << " ";
    if ( i % 15 == 14 )
      fprintf(stdout, "\n");
  }
  fprintf(stdout, "\n");

  cout << "Total Running Time: " << running << "\n";

  return 0;
}

vector<u64> center_lift(Plaintext plaintext, u64 size, u64 modulus) {
	vector<u64> ret(size);
	
	for (int i = 0; i < plaintext.coeff_count(); i++) {
		ret[i] = (plaintext[i] > modulus/2) ? plaintext[i]-modulus : plaintext[i];
	}

	return ret;
}

vector<vector<u64>> load_image(const char* filename, i64* channels, i64* width, i64* height) {
  FILE* fptr = fopen(filename, "r");

  fscanf(fptr, "%ld %ld %ld\n", channels, height, width);

  i64 i, j, x;
  i64 image_size = (*width) * (*height);
  vector<vector<u64>> image(*channels, vector<u64>(image_size,0));

  for (i = 0; i < *channels; i++) {
    for (j = 0; j < image_size; j++) {
      fscanf(fptr, "%lu", &(x));
      image[i][j] = x;
    }
  }

  fclose(fptr);
  return image;
}

void mean_pooling(vector<vector<u64>> &image) {
  u64 channels = image.size();
  u64 image_size = image[0].size();
  u64 image_width = (u64)sqrt((double)image_size);
  u64 image_height = image_width;
  u64 filter_width = 2;
  u64 filter_height = 2;
  u64 pooled_width = image_width / filter_width;
  u64 pooled_height = image_height / filter_height;

  u64 sum;
  for (u64 chan = 0; chan < channels; chan++) {
    vector<u64> pooled( pooled_width*pooled_height, 0);
    for (u64 i = 0; i < pooled_width; i++) {
      for (u64 j = 0; j < pooled_height; j++) {
        sum = 0;
        for (u64 ii = 0; ii < filter_width; ii++) {
          for (u64 ji = 0; ji < filter_height; ji++) {
            sum += image[chan][ ((2*i+ii)*image_width) + 2*j + ji ];
          }
        }
        pooled[(i*pooled_width)+j] = sum / (filter_width*filter_height);
      }
    }
    image[chan].swap(pooled);
  }
}

void pad_image(vector<u64> &image) {
  u64 size = image.size();
  u64 width = (u64) sqrt((double)size);

  vector<u64> padded;
  for (u64 i = 0; i < width+2; i++) {
    padded.push_back(0);
  }

  for (u64 i = 0; i < size; i++) {
    if (i % width == 0) {
      padded.push_back(0);
    }
    padded.push_back(image[i]);
    if (i % width == width-1) {
      padded.push_back(0);
    }
  }

  for (u64 i = 0; i < width+2; i++) {
    padded.push_back(0);
  }

  image.swap(padded);
}

void pad_images(vector<vector<u64>> &images) {
  for (u64 i = 0; i < images.size(); i++) {
    pad_image(images[i]);
  }
}

vector<vector<vector<u64>>> load_conv_weights(const char* filename) {
  FILE* fptr = fopen(filename, "r");

  i64 filters, channels, height, width;

  fscanf(fptr, "%ld %ld %ld %ld\n", &filters, &channels, &height, &width);

  i64 i, j, k, x;
  i64 filter_size = width * height;
  vector<vector<vector<u64>>> filter(filters, vector<vector<u64>>(channels, vector<u64>(filter_size, 0)));

  for (i = 0; i < filters; i++) {
    for (j = 0; j < channels; j++) {
      for (k = 0; k < filter_size; k++) {
        fscanf(fptr, "%lu", &(x));
        filter[i][j][k] = x;
      }
    }
  }

  fclose(fptr);
  return filter;
}

void prepare_filter(vector<vector<vector<u64>>> &filter, u64 image_width) {
  for (i64 i = 0; i < filter.size(); i++) {
    for (i64 j = 0; j < filter[i].size(); j++) {
      u64 filter_size = filter[i][j].size();
      u64 filter_width = (u64) sqrt((double)filter_size);
      vector<u64> remapped(filter_width*image_width, 0);
      u64 displacement = 0;
      for (i64 k = 0; k < filter[i][j].size(); k++) {
        remapped[k + displacement] = filter[i][j][filter_size-k-1];
        if (k % filter_width == filter_width-1) {
          displacement += image_width - filter_width;
        }
      }
      filter[i][j].swap(remapped);
    }
  }
}

void batch_filter(vector<vector<vector<u64>>> &filter, u64 image_size, u64 &filters_per_ciphertext) {
  u64 images_per_ciphertext = min(POLY_DEGREE / image_size, filter.size());
  // u64 images_per_ciphertext = min(POLY_DEGREE / image_size - (u64)(POLY_DEGREE%image_size != 0), filter.size());
  // images_per_ciphertext = 1;
  // while (filter.size() % images_per_ciphertext != 0)
    // images_per_ciphertext--;
  cout << "images_per_ciphertext: " << images_per_ciphertext << "\n";
  filters_per_ciphertext = images_per_ciphertext;

  u64 uneven_filters = (filter.size()%images_per_ciphertext > 0);

  vector<vector<vector<u64>>> batched(filter.size()/images_per_ciphertext + uneven_filters, vector<vector<u64>>(filter[0].size(), vector<u64>(POLY_DEGREE, 0)));

  for (u64 ff = 0; ff < filter.size(); ff += images_per_ciphertext) {
    for (u64 chan = 0; chan < filter[0].size(); chan++) {
      for (u64 fi = 0; fi < images_per_ciphertext && (fi+ff < filter.size()); fi++) {
        for (u64 i = 0; i < filter[0][0].size(); i++) {
          batched[ff/images_per_ciphertext][chan][(fi*image_size)+i] = filter[ff+fi][chan][i];
        }
      }
    }
  }

  filter.swap(batched);
}

vector<vector<u64>> unbatch_results(Plaintext plaintext, u64 image_size, u64 filters_per_ciphertext) {
  vector<vector<u64>> unbatched;
  vector<u64> center_lifted = center_lift(plaintext, plaintext.coeff_count(), PLAINTEXT_MOD);
  // cout << "filters_per_ciphertext: " << filters_per_ciphertext << "\n";
  // cout << "image_size: " << image_size << "\n";
  // cout << "center_lifted.size(): " << center_lifted.size() << "\n";
  // unbatched.push_back(center_lifted);

  for (u64 i = 0; i < filters_per_ciphertext; i++) {
    vector<u64> image_i(image_size, 0);
    for (u64 j = 0; j < image_size; j++) {
      image_i[j] = center_lifted[(i*image_size)+j];
    }
    unbatched.push_back(image_i);
  }

  return unbatched;
}

void reformat_image(vector<u64> &image, u64 size, u64 filter_size) {
  size = image.size();
  // cout << "reformat size: " << size << "\n";
  u64 image_width = (u64) sqrt((double)size);
  u64 image_height = image_width;
  u64 filter_width = (u64) sqrt((double)filter_size);
  u64 filter_height = filter_width;

  u64 start_position = (image_width * (filter_height-1)) + filter_width - 1;

  u64 temp;
  u64 new_image_index = 0;
  for (u64 i = start_position; i < image_width*image_height; i += image_width) {
    for (u64 j = 0; j < image_width - filter_width + 1; j++) {
      temp = image[i+j];
      image[i+j] = image[new_image_index];
      image[new_image_index] = temp;
      new_image_index++;
    }
  }
}

void scale_image(vector<u64> &image, u64 scale) {
  for (u64 i = 0; i < image.size(); i++) {
    i64 x = (i64)image[i];
    image[i] = (u64)(x / scale);
  }
}

void ReLU_image(vector<u64> &image) {
  for (u64 i = 0; i < image.size(); i++) {
    if ( ((i64)image[i]) < 0 ) {
      image[i] = 0;
    }
  }
}

void conv_layer(const char* filename, vector<vector<u64>> &input_layer, int padded, Encryptor &encryptor, Evaluator &evaluator, Decryptor &decryptor) {
  
  if (padded) {
    pad_images(input_layer);
  }

  u64 channels = input_layer.size();
  u64 size = input_layer[0].size();
  u64 width = (u64) sqrt((double)size);

  // cout << "size: " << size << "\n";
  // cout << "width: " << width << "\n";
  // cout << "channels: " << channels << "\n";

  vector<vector<vector<u64>>> filter = load_conv_weights(filename);
  u64 filter_size = filter[0][0].size();
  u64 filter_width = (u64)sqrt((double)filter_size);
  // cout << "filter_size: " << filter_size << "\n";
  // cout << "filter_width: " << filter_width << "\n";
  // cout << "ff: " << filter.size() << "\n";
  // cout << "fc: " << filter[0].size() << "\n";
  u64 output_filters = filter.size();

  // client side pre-processing
  vector<Ciphertext> ct_images;
  for (i64 i = 0; i < channels; i++) {
    vector<u64> extended(POLY_DEGREE, 0);
    for (i64 j = 0; j < input_layer[i].size(); j++) {
      extended[j] = input_layer[i][j];
    }

    Ciphertext x_encrypted;
    Plaintext x_plain(extended, POLY_DEGREE);

    encryptor.encrypt(x_plain, x_encrypted); 
    ct_images.push_back(x_encrypted);
  }

  // Prepare filter for conv layer
  prepare_filter(filter, width);

  // batch filters
  u64 filters_per_ciphertext;
  batch_filter(filter, size, filters_per_ciphertext);

  // create zero_cts for outputs
  vector<Ciphertext> ct_outputs;
  for (i64 i = 0; i < filter.size(); i++) {
    vector<u64> zero_vec(POLY_DEGREE, 0);
    Plaintext zero(zero_vec, POLY_DEGREE);
    Ciphertext x_encrypted;

    encryptor.encrypt(zero, x_encrypted);
    ct_outputs.push_back(x_encrypted);
  }

  // perform convolution step with multiplication
  u64 ff = filter.size();
  for (u64 chan = 0; chan < channels; chan++) {
    for (u64 fi = 0; fi < ff; fi++) {

      // vector<u64> extended(POLY_DEGREE, 0);
      // for (i64 j = 0; j < filter[fi][chan].size(); j++) {
      //   extended[j] = filter[fi][chan][j];      
      // }
      vector<u64> extended = filter[fi][chan];

      // without batching this needs to be set as we cannot have empty ciphertexts
      // from multiplying a ciphertext by zero (this continue skips that)
      // if (filter_size == 1 && extended[0] == 0) {
      //   continue;
      // }

      Ciphertext temp;
      Plaintext filter_plain(extended, POLY_DEGREE);

      evaluator.multiply_plain(ct_images[chan], filter_plain, temp);
      evaluator.add_inplace(ct_outputs[fi], temp);
    }
  }

  // decrypt the results
  vector<vector<u64>> outputs;
  for (i64 fi = 0; fi < ff; fi++) {
    Plaintext x_decrypted;
    decryptor.decrypt(ct_outputs[fi], x_decrypted);

    // unbatch the results and the push the vectors into outputs
    vector<vector<u64>> unbatched = unbatch_results(x_decrypted, size, filters_per_ciphertext);
    for (u64 i = 0; i < unbatched.size(); i++) {
      outputs.push_back(unbatched[i]);
    }
    // outputs.push_back( center_lift(x_decrypted, x_decrypted.coeff_count(), PLAINTEXT_MOD) );
  }
  outputs.resize(output_filters);

  size = (width - filter_width+1) * (width-filter_width+1);
  // reformat, relu, scale-down the images
  for (u64 i = 0; i < outputs.size(); i++) {
    reformat_image(outputs[i], size, filter_size);
    ReLU_image(outputs[i]);
    scale_image(outputs[i], 256);
    outputs[i].resize(size);
  }

  input_layer.swap(outputs);
  return;
}
