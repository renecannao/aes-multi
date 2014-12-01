/*

    Copyright (C) 2014 , Rene' Cannao' , rene.cannao@gmail.com
    This file is part of aes-multi.

    aes-multi is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Foobar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
*/

/* To compile:
   cc -o aes-multi aes-multi.c -lcrypto -lpthread 
*/

/*
  Code based on AES encryption/decryption demo program using OpenSSL EVP apis :
  https://github.com/saju/misc/blob/master/misc/openssl_aes.c
  this is public domain code. 
  Saju Pillai (saju.pillai@gmail.com)

*/


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <assert.h>


// Currently it uses 8 threads, hardcoded: future version will have this parameter configurable.
#define NUM_THREADS 8

// Threads run into a spin loop. Future version will implement a producer/consumer algorithm
#define USLEEP_TIME	50

#define BSIZE	10240


typedef struct __thr_data {
	pthread_t thr_id;
	unsigned int id;
	pthread_mutex_t mu;
	pthread_cond_t sig_producer;
	pthread_cond_t sig_consumer;
	int _lock;
	int _init;
	int bufsize;
	char *buff;
	unsigned char *ciphertext;
} _thr_data;


unsigned int salt[2];


_thr_data **THD=NULL;
__thread unsigned char key[32];
__thread unsigned char iv[32];

int decrypt=0;
unsigned char *key_data;
int key_data_len;

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 1;

  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */

  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len, int *retlen)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int rc=0;
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	//fprintf(stderr, "Line: %d -- len: %d , c_len: %d , f_len: %d\n", __LINE__, *len, c_len, f_len);
  unsigned char *ciphertext = malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
	rc=EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
//  rc=EVP_EncryptInit_ex(e, EVP_aes_256_cbc(), NULL, key, iv);
	assert(rc==1);
  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  rc=EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
	assert(rc==1);

  /* update ciphertext with the final remaining bytes */
	  rc=EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);
		assert(rc==1);

  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}


void * consumer_thread(void *arg) {
	unsigned int bytes_processed=0;
	_thr_data *thd=(_thr_data *)arg;
  EVP_CIPHER_CTX en, de;
  if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) {
    fprintf(stderr,"Couldn't initialize AES cipher\n");
    exit(EXIT_FAILURE);
  }

//	pthread_mutex_lock(&thd->mu);
//		pthread_cond_signal(&thd->sig_producer);
//	pthread_cond_wait(&thd->sig_consumer, &thd->mu);
	int t=1;

//	pthread_mutex_lock(&thd->mu);
//	if (thd->bufsize >= 0) pthread_cond_wait(&thd->sig_consumer, &thd->mu);

	while (t) {
	while (__sync_add_and_fetch(&thd->_lock,0) != 1) { usleep(USLEEP_TIME); }
//	while (thd->bufsize >= 0) {
		//fprintf(stderr,"Line: %d -- Consumer reading buff %d\n", __LINE__, thd->bufsize);
//		pthread_cond_wait(&thd->sig_consumer, &thd->mu);
		//if (thd->bufsize >= 0) pthread_cond_wait(&thd->sig_consumer, &thd->mu);
		//if (thd->bufsize == 0) pthread_cond_wait(&thd->sig_consumer, &thd->mu);
//		if (__sync_add_and_fetch(&thd->_lock,0)==0) pthread_cond_wait(&thd->sig_consumer, &thd->mu);
//		if (thd->bufsize==0) {
//			fprintf(stderr,"Line: %d -- Consumer mutex unlock\n", __LINE__);
//			pthread_mutex_unlock(&thd->mu);
//			continue;
//		}
		if (thd->bufsize==-1) {
//			pthread_mutex_unlock(&thd->mu);
			t=0;
			__sync_sub_and_fetch(&thd->_lock,1);
			continue;
		}
		
//		pthread_cond_signal(&thd->sig_producer);
		//unsigned char *ciphertext;
		//fprintf(stderr,"%d\n", rb);
		if (decrypt) {
			thd->ciphertext=aes_decrypt(&de, thd->buff, &thd->bufsize);
		} else {
			thd->ciphertext=aes_encrypt(&en, thd->buff, &thd->bufsize, NULL);
		}
		__sync_sub_and_fetch(&thd->_lock,1);
		//write(1,ciphertext,rl);
//		int rc=write(1,ciphertext,thd->bufsize);
//		assert(rc==thd->bufsize);
//		free(thd->ciphertext);
		
	}	
  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);
	return NULL;
}


int main(int argc, char **argv)
{

	int i;
	THD=malloc(sizeof(_thr_data *)*NUM_THREADS);
	assert(THD);
	for (i=0; i<NUM_THREADS; i++) {
		THD[i]=malloc(sizeof(_thr_data));
		assert(THD[i]);
//		pthread_mutex_init(&(THD[i]->mu),NULL);
//		pthread_cond_init(&(THD[i]->sig_producer),NULL);
//		pthread_cond_init(&(THD[i]->sig_consumer),NULL);
		THD[i]->bufsize=0;
		THD[i]->buff=malloc(BSIZE+AES_BLOCK_SIZE);
		assert(THD[i]->buff);
		THD[i]->_lock=0;
		THD[i]->_init=0;
		THD[i]->id=i;
	};



	if (argc!=3) {
		fprintf(stderr,"Usage: aes [ -c | -d ] key\n");
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1],"-d")==0) {
		decrypt=1;
	} else {
		if (strcmp(argv[1],"-c")!=0) {
			fprintf(stderr,"Specify -c or -d\n");
			return -1;
		}
	}

  key_data = (unsigned char *)argv[2];
  key_data_len = strlen(argv[2]);
  

	int rb=0;
	char buf[BSIZE+AES_BLOCK_SIZE];

	if (decrypt) {
		rb=fread(buf,1,8,stdin);
		rb=fread((unsigned char *)&salt,1,8,stdin);
	} else {
		srand(time(NULL)*getpid());
		salt[0]=rand();
		salt[1]=rand();
		fwrite("Salted__",8,1,stdout);
		fwrite((unsigned char *)&salt,8,1,stdout);
	}

	for (i=0;i<NUM_THREADS;i++) {
		pthread_create(&THD[i]->thr_id, NULL, consumer_thread, THD[i]);
	}


//	for (i=0;i<NUM_THREADS;i++) {
//		pthread_mutex_lock(&THD[i].mu);
//	}	
//	for (i=0;i<NUM_THREADS;i++) {
//		pthread_mutex_unlock(&THD[i].mu);
//	}	



	int maxread=BSIZE;
	int curr_thread=NUM_THREADS-1;
	if (decrypt) maxread+=AES_BLOCK_SIZE;
	while(rb=fread(buf,1,maxread,stdin)) {
		curr_thread++;
		if (curr_thread==NUM_THREADS) curr_thread=0;
		while (__sync_add_and_fetch(&THD[curr_thread]->_lock,0) != 0) { usleep(10); }
//		pthread_mutex_lock(&THD[curr_thread]->mu);
		if (THD[curr_thread]->bufsize > 0) {
			int rc=fwrite(THD[curr_thread]->ciphertext,THD[curr_thread]->bufsize,1,stdout);
			free(THD[curr_thread]->ciphertext);
		}

		THD[curr_thread]->bufsize=rb;
		memcpy(THD[curr_thread]->buff,buf,rb);
		__sync_add_and_fetch(&THD[curr_thread]->_lock,1);
	}

	for (i=0; i<NUM_THREADS; i++) {
		curr_thread++;
		if (curr_thread==NUM_THREADS) curr_thread=0;
		while (__sync_add_and_fetch(&THD[curr_thread]->_lock,0) != 0) { usleep(10); }
		if (THD[curr_thread]->bufsize > 0) {
			int rc=fwrite(THD[curr_thread]->ciphertext,THD[curr_thread]->bufsize,1,stdout);
			free(THD[curr_thread]->ciphertext);
		}
		THD[curr_thread]->bufsize=-1;
		__sync_add_and_fetch(&THD[curr_thread]->_lock,1);
	}

		
	for (i=0;i<NUM_THREADS;i++) {
		pthread_join(THD[i]->thr_id, NULL);
	}


  return 0;
}
  
