#include <stdio.h>
#include "seal/seal.h"
#include <iostream>
#include <fstream> #include <string>

#include "base64.h"

using namespace std;
using namespace seal;

int main()
{
  printf("hello, world\n");

  fstream newfile;

  string seed_b64;

  newfile.open("seed.txt", ios::in);
  if (newfile.is_open())
  {
    string tp;
    while (getline(newfile, tp))
    {
      seed_b64 = tp;
    }
    newfile.close();
  }

  // cout << seed_b64 << endl;

  vector<unsigned char> v;
  algorithm::decode_base64(seed_b64, v);
  // for (vector<unsigned char>::const_iterator it=v.begin(); it!=v.end(); ++it){
  //   //cout << std::hex << static_cast<int>(*it);
  //   printf("%d ", static_cast<int>(*it));
  // }
  cout << v.size() << endl;
  cout << endl;
  for (int i = 0; i < v.size(); i++)
  {
    printf("%d ", v[i]);
  }
  cout << endl;
  cout << v.size() << endl;

  EncryptionParameters parms(scheme_type::ckks);

  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

  // UniformRandomGeneratorFactory tmp_factory = UniformRandomGeneratorFactory();
  // parms.set_random_generator(std::make_shared(tmp_factory));

  prng_seed_type custom_seed;
  cout << "custom_seed" << endl;
  for (int i = 0; i < prng_seed_uint64_count; i++)
  {
    // custom_seed[i] = 1;
    custom_seed[i] = v[i];
  }

  printf("\n\ncustom seed from qo\n");
  for (int i = 0; i < custom_seed.size(); i++)
  {
    printf("%ld, ", custom_seed[i]);
  }
  printf("\n");
  double scale = pow(2.0, 40);

  SEALContext context(parms);


  // random seed
  //KeyGenerator keygen(context);

  // custom seed
  KeyGenerator keygen;
  keygen.sk_generated_ = false;
  keygen.context_ = context;
  auto &context_data = *context.key_context_data();
  auto &parms_context = context_data.parms();
  auto &coeff_modulus = parms_context.coeff_modulus();
  size_t coeff_count = parms_context.poly_modulus_degree();
  size_t coeff_modulus_size = coeff_modulus.size();

  auto secret_key_ = SecretKey();
  secret_key_.data().resize(seal::util::mul_safe(coeff_count, coeff_modulus_size));

  auto random_generator = parms_context.random_generator();
  cout << random_generator->use_random_seed_ << endl;
  random_generator->use_random_seed_ = false;
  cout << random_generator->use_random_seed_ << endl;
  auto prng = random_generator->create(custom_seed);

  keygen.generate_sk(prng);

  SecretKey secret_key = keygen.secret_key();
  Plaintext sk_pk = secret_key.sk_;
  auto sk_data = sk_pk.data_;
  cout << sk_data.size() << endl;
  //for(int i=0; i<10; i++){
  //  printf("%ld, ", sk_data[i]);
  //}
  //printf("\n");
  PublicKey public_key;
  keygen.create_public_key(public_key);
  RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);
  GaloisKeys gal_keys;
  keygen.create_galois_keys(gal_keys);
  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);

  CKKSEncoder encoder(context);
  size_t slot_count = encoder.slot_count();
  cout << "Number of slots: " << slot_count << endl;

  vector<double> test1 = {1.0, 2.0, 3.0};
  Plaintext p1;
  encoder.encode(test1, scale, p1);
  Ciphertext c1;
  encryptor.encrypt(p1, c1);
  Plaintext d1;
  decryptor.decrypt(c1, d1);
  vector<double> res1;
  encoder.decode(d1, res1);
  for(int i=0; i<5; i++){
    printf("%lf, ", res1[i]);
    //cout << res1[i] << endl;
  }
  printf("\n");


  //RandomToStandardAdapter engine(prng);
  //uniform_int_distribution<uint64_t> dist(0, 2);

  //for (int i = 0; i < 10; i++)
  //{
  //  uint64_t rand = dist(engine);
  //  printf("%ld, ", rand);
  //}
  //printf("\n");

  // SEAL_ITERATE(iter(secret_key), coeff_count, [&](auto &I) {
  //     uint64_t rand = dist(engine);
  //     uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(rand == 0));
  //     SEAL_ITERATE(
  //         iter(seal::util::StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus), coeff_modulus_size,
  //         [&](auto J) { *get<0>(J) = rand + (flag & get<1>(J).value()) - 1; });
  // });

  // cout << "tmp4" << endl;
  // auto secret_key = keygen.secret_key();
}
