#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>


char buffer[1024];
const int MAX_DIGITS = 50;
int i,j = 0;

struct public_key_class{
  long long modulus;
  long long exponent;
};

struct private_key_class{
  long long modulus;
  long long exponent;
};


// This should totally be in the math library.
long long gcd(long long a, long long b)
{
  long long c;
  while ( a != 0 ) {
    c = a; a = b%a;  b = c;
  }
  return b;
}


long long ExtEuclid(long long a, long long b)
{
 long long x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
 while (a!=0) {
   q = gcd/a; r = gcd % a;
   m = x-u*q; n = y-v*q;
   gcd = a; a = r; x = u; y = v; u = m; v = n;
   }
   return y;
}

__global__ void rsa_modExp(long long b, long long e, long long m, long long* array)
{
  if (b < 0 || e < 0 || m <= 0){
    printf("error arguments.\n");
  }

  int index = blockDim.x * blockIdx.x + threadIdx.x;
  int thread_nums = gridDim.x * blockDim.x;

  long long en_result = 1;
 
	long long i;
	for(i = index; i < e ; i+=thread_nums){
		//t_result = en_result % m;
		en_result = (en_result * b)% m;
  }
  if (index < e){
    array[index] = en_result;
  }
  else {
    array[index] = 0;
  }
	//return en_result;
	

}

// Calling this function will generate a public and private key and store them in the pointers
// it is given. 
void rsa_gen_keys(struct public_key_class *pub, struct private_key_class *priv, char *PRIME_SOURCE_FILE)
{
  FILE *primes_list;
  if(!(primes_list = fopen(PRIME_SOURCE_FILE, "r"))){
    fprintf(stderr, "Problem reading %s\n", PRIME_SOURCE_FILE);
    exit(1);
  }

  // count number of primes in the list
  long long prime_count = 0;
  do{
    int bytes_read = fread(buffer,1,sizeof(buffer)-1, primes_list);
    buffer[bytes_read] = '\0';
    for (i=0 ; buffer[i]; i++){
      if (buffer[i] == '\n'){
	prime_count++;
      }
    }
  }
  while(feof(primes_list) == 0);
  
  
  // choose random primes from the list, store them as p,q

  long long p = 0;
  long long q = 0;

  long long e = powl(2, 8) + 1;
  long long d = 0;
  char prime_buffer[MAX_DIGITS];
  long long max = 0;
  long long phi_max = 0;
  
  srand(time(NULL));
  
  do{
    // a and b are the positions of p and q in the list
    int a =  (double)rand() * (prime_count+1) / (RAND_MAX+1.0);
    int b =  (double)rand() * (prime_count+1) / (RAND_MAX+1.0);
    
    // here we find the prime at position a, store it as p
    rewind(primes_list);
    for(i=0; i < a + 1; i++){
    //  for(j=0; j < MAX_DIGITS; j++){
    //	prime_buffer[j] = 0;
    //  }
      fgets(prime_buffer,sizeof(prime_buffer)-1, primes_list);
    }
    p = atol(prime_buffer); 
    
    // here we find the prime at position b, store it as q
    rewind(primes_list);
    for(i=0; i < b + 1; i++){
      for(j=0; j < MAX_DIGITS; j++){
	prime_buffer[j] = 0;
      }
      fgets(prime_buffer,sizeof(prime_buffer)-1, primes_list);
    }
    q = atol(prime_buffer); 

    //here
    p = 8011;
    q = 8521;

    max = p*q;
    phi_max = (p-1)*(q-1);
  }
  while(!(p && q) || (p == q) || (gcd(phi_max, e) != 1));
 
  // Next, we need to choose a,b, so that a*max+b*e = gcd(max,e). We actually only need b
  // here, and in keeping with the usual notation of RSA we'll call it d. We'd also like 
  // to make sure we get a representation of d as positive, hence the while loop.
  d = ExtEuclid(phi_max,e);
  while(d < 0){
    d = d+phi_max;
  }

  printf("primes are %lld and %lld\n",(long long)p, (long long )q);
  // We now store the public / private keys in the appropriate structs

  //here
  d = 41956193;

  pub->modulus = max;
//pub->modulus = 2936519639;
  pub->exponent = e;
//pub->exponent = 257;
  priv->modulus = max;
//priv->modulus = 2936519639;
  priv->exponent = d;
  //priv->exponent = 1988060033;
}


long long *rsa_encrypt(const char *message, const unsigned long message_size, 
                     const struct public_key_class *pub)
{
  long long *encrypted = (long long *)malloc(sizeof(long long)*message_size);
  if(encrypted == NULL){
    fprintf(stderr,
     "Error: Heap allocation failed.\n");
    return NULL;
  }

  long long i = 0;
  long long j = 0;
  dim3 dimBlock(512);
  dim3 dimGrid(16);

  int size = 512 * 16 * sizeof(long long);
  long long *array;
  long long host_array[size];
  cudaMalloc((void**)&array, size);
  long long result = 1;

  for(i=0; i < message_size; i++){
    rsa_modExp<<<dimGrid, dimBlock>>>(message[i], pub->exponent, pub->modulus, array);

    cudaMemcpy(host_array, array, size, cudaMemcpyDeviceToHost);

    result = 1;
    for(j=0; j < 512 * 16; j++){
      if (j < pub->exponent) {
        result = (result * host_array[j]) % pub->modulus;
      }
    }
    
    encrypted[i] = result;
  }
  return encrypted;
}


char *rsa_decrypt(const long long *message, 
                  const unsigned long message_size, 
                  const struct private_key_class *priv)
{
  if(message_size % sizeof(long long) != 0){
    fprintf(stderr,
     "Error: message_size is not divisible by %d, so cannot be output of rsa_encrypt\n", (int)sizeof(long long));
     return NULL;
  }
  // We allocate space to do the decryption (temp) and space for the output as a char array
  // (decrypted)
  char *decrypted = (char *)malloc(message_size/sizeof(long long));
  char *temp = (char *)malloc(message_size);
  if((decrypted == NULL) || (temp == NULL)){
    fprintf(stderr,
     "Error: Heap allocation failed.\n");
    return NULL;
  }
  // Now we go through each 8-byte chunk and decrypt it.
  long long i = 0;
  long long j = 0;
  dim3 dimBlock(512);
  dim3 dimGrid(16);

  int size = 512 * 16 * sizeof(long long);
  long long *array;
  long long host_array[size];

  cudaMalloc((void**)&array, size);
  long long result = 1;

  for(i=0; i < message_size/8; i++){
    rsa_modExp<<<dimGrid, dimBlock>>>(message[i], priv->exponent, priv->modulus, array);

    cudaMemcpy(host_array, array, size, cudaMemcpyDeviceToHost);

    result = 1;
    for(j=0; j < 512 * 16 ; j++){
      if (j < priv->exponent) {
        result = (result * host_array[j]) % priv->modulus;
      }
    }

    temp[i] = result;
  }

  // The result should be a number in the char range, which gives back the original byte.
  // We put that into decrypted, then return.
  for(i=0; i < message_size/8; i++){
    decrypted[i] = temp[i];
  }
  free(temp);
  return decrypted;
}

int main(int argc, char **argv)
{
  char *PRIME_SOURCE_FILE = "primes.txt";
  struct public_key_class pub[1];
  struct private_key_class priv[1];
  rsa_gen_keys(pub, priv, PRIME_SOURCE_FILE);

  printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)priv->modulus, (long long) priv->exponent);
  printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
  
  FILE* fptr = fopen("test.txt", "r");
  if(fptr == NULL){
	  printf("e1\n");
  }
  int filesize = fseek(fptr, 0, SEEK_END);
  char* buff = (char*)malloc(100 * sizeof(char));
  fseek(fptr, 0, SEEK_SET);
  int n = fread(buff, 100, 1, fptr);
  
  char message[101];
  strncpy(message, buff, sizeof(message)-1); 
  message[100] = '\0';

  int i;

  printf("Original:\n");
  //for(i=0; i < strlen(message); i++){
    //printf("%lld\n", (long long)message[i]);
	printf("%s\n", message);
  //}  
  
  long long *encrypted = rsa_encrypt(message, sizeof(message), pub);
  if (!encrypted){
    fprintf(stderr, "Error in encryption!\n");
    return 1;
  }
  printf("Encrypted:\n");
  for(i=0; i < strlen(message); i++){
    printf("%lld\n", (long long)encrypted[i]);
  }  
  
  char *decrypted = rsa_decrypt(encrypted, 8*sizeof(message), priv);
  if (!decrypted){
    fprintf(stderr, "Error in decryption!\n");
    return 1;
  }
  printf("Decrypted:\n");
  //for(i=0; i < strlen(message); i++){
    //printf("%lld\n", i, (long long)decrypted[i]);
	//printf("%s\n", decrypted);
  //}  
  
  FILE* fptr1 = fopen(argv[argc - 1], "w");
  fwrite(decrypted, 100, 1, fptr1);
  
  printf("\n");
  free(encrypted);
  free(decrypted);
  free(buff);
  fclose(fptr1);
  fclose(fptr);
  return 0;
}
