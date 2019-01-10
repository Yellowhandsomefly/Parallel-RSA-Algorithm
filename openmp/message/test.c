#include <stdio.h>
#include "rsa.h"
#include <string.h>
#include <stdlib.h>
#include <omp.h>

const int READ_SIZE = 100;

int main(int argc, char **argv)
{
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
  char* buff = (char*)malloc(READ_SIZE * sizeof(char));
  fseek(fptr, 0, SEEK_SET);
  int n = fread(buff, READ_SIZE, 1, fptr);
  
  char message[READ_SIZE + 1];
  strncpy(message, buff, sizeof(message)-1); 
  message[READ_SIZE] = '\0';

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
  fwrite(decrypted, READ_SIZE, 1, fptr1);
  
  printf("\n");
  free(encrypted);
  free(decrypted);
  free(buff);
  fclose(fptr1);
  fclose(fptr);
  return 0;
}