/****************************************************************************
*																			*
*					cryptlib PKC Keygen Header File 						*
*					Copyright Peter Gutmann 1997-2004						*
*																			*
****************************************************************************/

#ifndef _KEYGEN_DEFINED

#define _KEYGEN_DEFINED

/* The number of iterations of Miller-Rabin for an error probbility of
   (1/2)^80, from HAC */

#define getNoPrimeChecks( noBits ) \
	( ( noBits < 150 ) ? 18 : ( noBits < 200 ) ? 15 : \
	  ( noBits < 250 ) ? 12 : ( noBits < 300 ) ? 9 : \
	  ( noBits < 350 ) ? 8 : ( noBits < 400 ) ? 7 : \
	  ( noBits < 500 ) ? 6 : ( noBits < 600 ) ? 5 : \
	  ( noBits < 800 ) ? 4 : ( noBits < 1250 ) ? 3 : 2 )

/* Prototypes for functions in kg_prime.c */

BOOLEAN primeSieve( const BIGNUM *candidate );
int primeProbable( PKC_INFO *pkcInfo, BIGNUM *n, const int noChecks,
				   const void *callbackArg );
int generatePrime( PKC_INFO *pkcInfo, BIGNUM *candidate, const int noBits,
				   const long exponent, const void *callbackArg );

#endif /* _KEYGEN_DEFINED */

