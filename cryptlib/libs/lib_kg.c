/****************************************************************************
*																			*
*					cryptlib PKC Generation/Checking Routines				*
*				Copyright Peter Gutmann and Kevin Bluck 1997-2003			*
*																			*
****************************************************************************/

/* The Usenet Oracle has pondered your question deeply.
   Your question was:

   > O Oracle Most Wise,
   >
   > What is the largest prime number?

   And in response, thus spake the Oracle:

   } This is a question which has stumped some of the best minds in
   } mathematics, but I will explain it so that even you can understand it.
   } The first prime is 2, and the binary representation of 2 is 10.
   } Consider the following series:
   }
   }	Prime	Decimal Representation	Representation in its own base
   }	1st		2						10
   }	2nd		3						10
   }	3rd		5						10
   }	4th		7						10
   }	5th		11						10
   }	6th		13						10
   }	7th		17						10
   }
   } From this demonstration you can see that there is only one prime, and
   } it is ten. Therefore, the largest prime is ten.
													-- The Usenet Oracle */
#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/context.h"
#else
  #include "crypt.h"
  #include "misc/context.h"
#endif /* Compiler-specific includes */
#if defined( INC_ALL )
  #ifdef __TANDEMNSK__
	#include "bnprime.h"
  #else
	#include "bn_prime.h"
  #endif /* __TANDEMNSK__ */
#elif defined( INC_CHILD )
  #include "../bn/bn_prime.h"
#else
  #include "bn/bn_prime.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Determine Discrete Log Exponent Bits				*
*																			*
****************************************************************************/

/* The following function (provided by Colin Plumb) is used to calculate the
   appropriate size exponent for a given prime size which is required to
   provide equivalent security from small-exponent attacks

   This is based on a paper by Michael Wiener on	| The function defined
   the difficulty of the two attacks, which has		| below (not part of the
   the following table:								| original paper)
													| produces the following
	 Table 1: Subgroup Sizes to Match Field Sizes	| results:
													|
	Size of p	Cost of each attack		Size of q	|	Output	Error
	 (bits)		(instructions or		(bits)		|			(+ is safe)
				 modular multiplies)				|
													|
	   512			9 x 10^17			119			|	137		+18
	   768			6 x 10^21			145			|	153		+8
	  1024			7 x 10^24			165			|	169		+4
	  1280			3 x 10^27			183			|	184		+1
	  1536			7 x 10^29			198			|	198		+0
	  1792			9 x 10^31			212			|	212		+0
	  2048			8 x 10^33			225			|	225		+0
	  2304			5 x 10^35			237			|	237		+0
	  2560			3 x 10^37			249			|	249		+0
	  2816			1 x 10^39			259			|	260		+1
	  3072			3 x 10^40			269			|	270		+1
	  3328			8 x 10^41			279			|	280		+1
	  3584			2 x 10^43			288			|	289		+1
	  3840			4 x 10^44			296			|	297		+1
	  4096			7 x 10^45			305			|	305		+0
	  4352			1 x 10^47			313			|	313		+0
	  4608			2 x 10^48			320			|	321		+1
	  4864			2 x 10^49			328			|	329		+1
	  5120			3 x 10^50			335			|	337		+2

   This function fits a curve to this, which overestimates the size of the
   exponent required, but by a very small amount in the important 1000-4000
   bit range.  It is a quadratic curve up to 3840 bits, and a linear curve
   past that.  They are designed to be C(1) (have the same value and the same
   slope) at the point where they meet */

#define AN		1L		/* a = -AN/AD/65536, the quadratic coefficient */
#define AD		3L
#define M		8L		/* Slope = M/256, i.e. 1/32 where linear starts */
#define TX		3840L	/* X value at the slope point, where linear starts */
#define TY		297L	/* Y value at the slope point, where linear starts */

/* For a slope of M at the point (TX,TY), we only have one degree of freedom
   left in a quadratic curve, so use the coefficient of x^2, namely a, as
   that free parameter.

   y = -AN/AD*((x-TX)/256)^2 + M*(x-TX)/256 + TY
	 = -AN*(x-TX)*(x-TX)/AD/256/256 + M*x/256 - M*TX/256 + TY
	 = -AN*x*x/AD/256/256 + 2*AN*x*TX/AD/256/256 - AN*TX*TX/AD/256/256 \
		+ M*x/256 - M*TX/256 + TY
	 = -AN*(x/256)^2/AD + 2*AN*(TX/256)*(x/256)/AD + M*(x/256) \
		- AN*(TX/256)^2/AD - M*(TX/256) + TY
	 = (AN*(2*TX/256 - x/256) + M*AD)*x/256/AD - (AN*(TX/256)/AD + M)*TX/256 \
		+ TY
	 = (AN*(2*TX/256 - x/256) + M*AD)*x/256/AD \
		- (AN*(TX/256) + M*AD)*TX/256/AD + TY
	 =  ((M*AD + AN*(2*TX/256 - x/256))*x - (AN*(TX/256)+M*AD)*TX)/256/AD + TY
	 =  ((M*AD + AN*(2*TX - x)/256)*x - (AN*(TX/256)+M*AD)*TX)/256/AD + TY
	 =  ((M*AD + AN*(2*TX - x)/256)*x - (M*AD + AN*TX/256)*TX)/256/AD + TY
	 =  (((256*M*AD+2*AN*TX-AN*x)/256)*x - (M*AD + AN*TX/256)*TX)/256/AD + TY

   Since this is for the range 0...TX, in order to avoid having any
   intermediate results less than 0, we need one final rearrangement, and a
   compiler can easily take the constant-folding from there...

	 =  TY + (((256*M*AD+2*AN*TX-AN*x)/256)*x - (M*AD + AN*TX/256)*TX)/256/AD
	 =  TY - ((M*AD + AN*TX/256)*TX - ((256*M*AD+2*AN*TX-AN*x)/256)*x)/256/AD
*/

static int getDLPexpSize( const int primeBits )
	{
	long value;	/* Necessary to avoid braindamage on 16-bit compilers */

	/* If it's over TX bits, it's linear */
	if( primeBits > TX )
		value = M * primeBits / 256 - M * TX / 256 + TY;
	else
		/* It's quadratic */
		value = TY - ( ( M * AD + AN * TX / 256 ) * TX - \
					   ( ( 256 * M * AD + AN * 2 * TX - AN * primeBits ) / 256 ) * \
					   primeBits ) / ( AD * 256 );

	/* Various standards require a minimum of 160 bits so we always return at
	   least that size even if it's not necessary */
	return( value > 160 ? ( int ) value : 160 );
	}

/****************************************************************************
*																			*
*							Generate Random Bignum							*
*																			*
****************************************************************************/

/* Generate a bignum of a specified length, with the given high and low 8
   bits.  'high' is merged into the high 8 bits of the number (set it to 0x80
   to ensure that the number is exactly 'bits' bits long, i.e. 2^(bits-1) <=
   bn < 2^bits), 'low' is merged into the low 8 bits (set it to 1 to ensure
   that the number is odd).  In almost all cases used in cryptlib, 'high' is
   set to 0xC0 and low is set to 0x01.

   We don't need to pagelock the bignum buffer we're using because it's being
   accessed continuously while there's data in it, so there's little chance
   it'll be swapped unless the system is already thrashing */

int generateBignum( BIGNUM *bn, const int noBits, const BYTE high,
					const BYTE low )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int noBytes = bitsToBytes( noBits ), status;

	/* Clear the return value */
	BN_zero( bn );

	/* Load the random data into the bignum buffer */
	setMessageData( &msgData, buffer, noBytes );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		{
		zeroise( buffer, noBytes );
		return( status );
		}

	/* Merge in the specified low bits, mask off any excess high bits, and
	   merge in the specified high bits.  This is a bit more complex than
	   just masking in the byte values because the bignum may not be a
	   multiple of 8 bytes long */
	buffer[ noBytes - 1 ] |= low;
	buffer[ 0 ] &= 255 >> ( -noBits & 7 );
	buffer[ 0 ] |= high >> ( -noBits & 7 );
	if( noBytes > 1 && ( noBits & 7 ) )
		buffer[ 1 ] |= high << ( noBits & 7 );

	/* Turn the contents of the buffer into a bignum and zeroise the buffer */
	status = ( BN_bin2bn( buffer, noBytes, bn ) == NULL ) ? \
			 CRYPT_ERROR_MEMORY : CRYPT_OK;
	zeroise( buffer, noBytes );

	return( status );
	}

/****************************************************************************
*																			*
*							Generate Non-specific Primes					*
*																			*
****************************************************************************/

/* #include 4k of EAY copyright */

/* The following define is necessary in memory-starved environments.  It
   controls the size of the table used for the sieving */

#if defined( CONFIG_CONSERVE_MEMORY )
  #define EIGHT_BIT
#endif /* CONFIG_CONSERVE_MEMORY */

/* The number of primes in the sieve (and their values) that result in a
   given number of candidates remaining from 40,000.  Even the first 100
   primes weed out 91% of all the candidates, and after 500 you're only
   removing a handful for each 100 extra primes.

	 Number		   Prime	Candidates left
				  Values	from 40,000
	--------	---------	---------------
	  0- 99		   0- 541		3564
	100-199		 541-1223		3175
	200-299		1223-1987		2969
	300-399		1987-2741		2845
	400-499		2741-3571		2755
	500-599		3571-4409		2688
	600-699		4409-5279		2629
	700-799		5279-6133		2593
	800-899		6133-6997		2555
	900-999		6997-7919		2521

  There is in fact an even faster prime tester due to Dan Piponi that uses
  C++ templates as a universal computer and performs the primality test at
  compile time, however this requires the use of a fairly advanced C++
  compiler and isn't amenable to generating different primes */

/* The number of iterations of Miller-Rabin for an error probbility of
   (1/2)^80, from HAC */

#define getNoPrimeChecks( noBits ) \
	( ( noBits < 150 ) ? 18 : ( noBits < 200 ) ? 15 : \
	  ( noBits < 250 ) ? 12 : ( noBits < 300 ) ? 9 : \
	  ( noBits < 350 ) ? 8 : ( noBits < 400 ) ? 7 : \
	  ( noBits < 500 ) ? 6 : ( noBits < 600 ) ? 5 : \
	  ( noBits < 800 ) ? 4 : ( noBits < 1250 ) ? 3 : 2 )

/* Enable the following to cross-check the Miller-Rabin test using a Fermat 
   test and an alternative form of the Miller-Rabin test that merges the
   test loop and the modexp at the start.  Note that this displays 
   diagnostic timing output and expects to use Pentium performance counters 
   for timing, so it's only (optionally) enabled for Win32 debug */

#if defined( __WIN32__ ) && !defined( NDEBUG ) && 0
  #define CHECK_PRIMETEST
#endif /* Win32 debug */

/* The size of the sieve array - 1 memory page (on most CPUs) = 4K candidate
   values.  When changing this value the LFSR parameters need to be adjusted
   to match */

#define SIEVE_SIZE				4096

/* When we're doing a sieve of a singleton candidate, we don't run through
   the whole range of sieve values since we run into the law of diminshing
   returns after a certain point.  The following value sieves with every
   prime under 1000 */

#if NUMPRIMES < ( 21 * 8 )
  #define FAST_SIEVE_NUMPRIMES	NUMPRIMES
#else
  #define FAST_SIEVE_NUMPRIMES	( 21 * 8 )
#endif /* Small prime table */

/* Set up the sieve array for the number.  Every position that contains
   a zero is non-divisible by all of the small primes */

static void initSieve( BOOLEAN *sieveArray, const BIGNUM *candidate )
	{
	int i;

	memset( sieveArray, 0, SIEVE_SIZE * sizeof( BOOLEAN ) );

	/* Walk down the list of primes marking the appropriate position in the
	   array as divisible by the prime.  We start at index 1, since the
	   candidate will never be divisible by 2 (== primes[ 0 ]) */
	for( i = 1; i < NUMPRIMES; i++ )
		{
		unsigned int step = primes[ i ];
		int sieveIndex = ( int ) BN_mod_word( candidate, step );

		/* Determine the correct start index for this value */
		if( sieveIndex & 1 )
			sieveIndex = ( step - sieveIndex ) / 2;
		else
			if( sieveIndex )
				sieveIndex = ( ( step * 2 ) - sieveIndex ) / 2;

		/* Mark each multiple of the divisor as being divisible */
		while( sieveIndex < SIEVE_SIZE )
			{
			sieveArray[ sieveIndex ] = 1;
			sieveIndex += step;
			}
		}
	}

/* An LFSR to step through each entry in the sieve array.  This isn't a true
   pseudorandom selection since all it's really doing is going through the
   numbers in a linear order with a different starting point, but it's good
   enough as a randomiser */

#define LFSR_POLYNOMIAL		0x1053
#define LFSR_MASK			0x1000

static int nextEntry( int value )
	{
	assert( LFSR_MASK == SIEVE_SIZE );

	/* Get the next value: Multiply by x and reduce by the polynomial */
	value <<= 1;
	if( value & LFSR_MASK )
		value ^= LFSR_POLYNOMIAL;
	return( value );
	}

/* A one-off sieve check for when we're testing a singleton rather than
   running over a range of values */

static BOOLEAN primeSieve( const BIGNUM *candidate )
	{
	int i;

	for( i = 1; i < FAST_SIEVE_NUMPRIMES; i++ )
		if( BN_mod_word( candidate, primes[ i ] ) == 0 )
			return( FALSE );

	return( TRUE );
	}

#ifdef CHECK_PRIMETEST

/* Witness function, modified from original BN code.  Found at a UFO crash 
   site.  This looks nothing like a standard Miller-Rabin test because it 
   merges the modexp that usually needs to be performed as the first 
   portion of the test process and the remainder of the checking.  Destroys 
   param6 + 7 */

static int witnessOld( PKC_INFO *pkcInfo, BIGNUM *a, BIGNUM *n, BIGNUM *n1, 
					   BIGNUM *mont_n1, BIGNUM *mont_1, 
					   BN_MONT_CTX *montCTX_n )
	{
	BIGNUM *y = &pkcInfo->param6;
	BIGNUM *yPrime = &pkcInfo->param7;		/* Safe to destroy */
	BN_CTX *ctx = &pkcInfo->bnCTX;
	BIGNUM *mont_a = &ctx->bn[ ctx->tos++ ];
	const int k = BN_num_bits( n1 );
	int i, bnStatus = BN_STATUS;

	/* All values are manipulated in their Montgomery form, so before we 
	   begin we have to convert a to this form as well */
	if( !BN_to_montgomery( mont_a, a, montCTX_n, &pkcInfo->bnCTX ) )
		{
		ctx->tos--;
		return( CRYPT_ERROR_FAILED );
		}

	CKPTR( BN_copy( y, mont_1 ) );
	for ( i = k - 1; i >= 0; i-- )
		{
		/* Perform the y^2 mod n check.  yPrime = y^2 mod n, if yPrime == 1
		   it's composite (this condition is virtually never met) */
		CK( BN_mod_mul_montgomery( yPrime, y, y, montCTX_n, 
								   &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) || \
			( !BN_cmp( yPrime, mont_1 ) && \
			  BN_cmp( y, mont_1 ) && BN_cmp( y, mont_n1 ) ) )
			{
			ctx->tos--;
			return( TRUE );
			}

		/* Perform another step of the modexp */
		if( BN_is_bit_set( n1, i ) )
			CK( BN_mod_mul_montgomery( y, yPrime, mont_a, montCTX_n, 
									   &pkcInfo->bnCTX ) );
		else
			{
			BIGNUM *tmp;

			/* Input and output to modmult can't be the same, so we have to
			   swap the pointers */
			tmp = y; y = yPrime; yPrime = tmp;
			}
		}
	ctx->tos--;

	/* Finally we have y = a^u mod n.  If y == 1 (mod n) it's prime,
	   otherwise it's composite */
	return( BN_cmp( y, mont_1 ) ? TRUE : FALSE );
	}

/* Perform noChecks iterations of the Miller-Rabin probabilistic primality 
   test.  Destroys param8, tmp1-3, mont1 */

static int primeProbableOld( PKC_INFO *pkcInfo, BIGNUM *candidate, 
							 const int noChecks, const void *callbackArg )
	{
	BIGNUM *check = &pkcInfo->tmp1;
	BIGNUM *candidate_1 = &pkcInfo->tmp2;
	BIGNUM *mont_candidate_1 = &pkcInfo->tmp3;
	BIGNUM *mont_1 = &pkcInfo->param8;		/* Safe to destroy */
	BN_MONT_CTX *montCTX_candidate = &pkcInfo->montCTX1;
	int i, bnStatus = BN_STATUS, status;

	/* Set up various values */
	CK( BN_MONT_CTX_set( montCTX_candidate, candidate, &pkcInfo->bnCTX ) );
	CK( BN_to_montgomery( mont_1, BN_value_one(), montCTX_candidate, 
						  &pkcInfo->bnCTX ) );
	CKPTR( BN_copy( candidate_1, candidate ) );
	CK( BN_sub_word( candidate_1, 1 ) );
	CK( BN_to_montgomery( mont_candidate_1, candidate_1, montCTX_candidate, 
						  &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Perform n iterations of Miller-Rabin */
	for( i = 0; i < noChecks; i++ )
		{
		const CONTEXT_INFO *contextInfoPtr = callbackArg;

		/* Check whether the abort flag has been set for an async keygen.
		   We do this before the Miller-Rabin check to ensure that it always 
		   gets called at least once for every call to primeProbable() - 
		   since the majority of candidates fail the witness() function, 
		   it'd almost never get called after witness() has been called */
		if( contextInfoPtr->flags & CONTEXT_ASYNC_ABORT )
			{
			status = ASYNC_ABORT;
			break;
			}

		/* Instead of using a bignum for the Miller-Rabin check, we use a
		   series of small primes.  The reason for this is that if bases a1
		   and a2 are strong liars for n then their product a1a2 is also very
		   likely to be a strong liar, so using a composite base doesn't give
		   us any great advantage.  In addition an initial test with a=2 is
		   beneficial since most composite numbers will fail Miller-Rabin
		   with a=2, and exponentiation with base 2 is faster than general-
		   purpose exponentiation.  Finally, using small values instead of
		   random bignums is both significantly more efficient and much
		   easier on the RNG.   In theory in order to use the first noChecks 
		   small primes as the base instead of using random bignum bases we 
		   would have to assume that the extended Riemann hypothesis holds 		   
		   (without this, which allows us to use values 1 < check < 
		   2 * log( candidate )^2, we'd have to pick random check values as 
		   required for Monte Carlo algorithms), however the requirement for 
		   random bases assumes that the candidates could be chosen 
		   maliciously to be pseudoprime to any reasonable list of bases, 
		   thus requiring random bases to evade the problem.  Obviously we're 
		   not going to do this, so one base is as good as another, and small 
		   primes work well (even a single Fermat test has a failure 
		   probability of around 10e-44 for 512-bit primes if you're not 
		   trying to cook the primes, this is why Fermat works as a 
		   verification of the Miller-Rabin test in generatePrime()) */
		BN_set_word( check, primes[ i ] );
		status = witnessOld( pkcInfo, check, candidate, candidate_1, 
							 mont_candidate_1, mont_1, montCTX_candidate );
		if( cryptStatusError( status ) )
			return( status );
		if( status )
			return( FALSE );	/* It's not a prime */
		}

	/* It's prime */
	return( TRUE );
	}
#endif /* CHECK_PRIMETEST */

/* Less unconventional witness function, which follows the normal pattern:

	x(0) = a^u mod n
	if x(0) = 1 || x(0) = n - 1 
		return "probably-prime"

	for i = 1 to k
		x(i) = x(i-1)^2 mod n
		if x(i) = n - 1
			return "probably-prime"
		if x(i) = 1
			return "composite";
	return "composite"

   Since it's a yes-biased Monte Carlo algorithm, this witness function can
   only answer "probably-prime", so we reduce the uncertainty by iterating
   for the Miller-Rabin test */

static int witness( PKC_INFO *pkcInfo, BIGNUM *a, const BIGNUM *n, 
					const BIGNUM *n_1, const BIGNUM *u, const int k, 
					BN_MONT_CTX *montCTX_n )
	{
	int i, bnStatus = BN_STATUS;

	/* x(0) = a^u mod n.  If x(0) == 1 || x(0) == n - 1 it's probably
	   prime */
	CK( BN_mod_exp_mont( a, a, u, n, &pkcInfo->bnCTX, montCTX_n ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	if( BN_is_one( a ) || !BN_cmp( a, n_1 ) )
		return( FALSE );	/* Probably prime */

	for( i = 1; i < k; i++ )
		{
		/* x(i) = x(i-1)^2 mod n */
		CK( BN_mod_mul( a, a, a, n, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		if( !BN_cmp( a, n_1 ) )
			return( FALSE );	/* Probably prime */
		if( BN_is_one( a ) )
			return( TRUE );		/* Composite */
		}

	return( TRUE );
	}

/* Perform noChecks iterations of the Miller-Rabin probabilistic primality 
   test (n = candidate prime, a = randomly-chosen check value):

	evaluate u s.t. n - 1 = 2^k * u, u odd

	for i = 1 to noChecks
		if witness( a, n, n-1, u, k )
			return "composite"

	return "prime"

  Destroys tmp1-3, mont1 */

static int primeProbable( PKC_INFO *pkcInfo, BIGNUM *n, const int noChecks, 
						  const void *callbackArg )
	{
	BIGNUM *a = &pkcInfo->tmp1, *n_1 = &pkcInfo->tmp2, *u = &pkcInfo->tmp3;
	int i, k, bnStatus = BN_STATUS, status;

	/* Set up various values */
	CK( BN_MONT_CTX_set( &pkcInfo->montCTX1, n, &pkcInfo->bnCTX ) );

	/* Evaluate u as n - 1 = 2^k * u.  Obviously the less one bits in the 
	   LSBs of n, the more efficient this test becomes, however with a 
	   randomly-chosen n value we get an exponentially-decreasing chance 
	   of losing any bits after the first one, which will always be zero 
	   since n starts out being odd */
	CKPTR( BN_copy( n_1, n ) );
	CK( BN_sub_word( n_1, 1 ) );
	for( k = 1; !BN_is_bit_set( n_1, k ); k++ );
	CK( BN_rshift( u, n_1, k ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Perform n iterations of Miller-Rabin */
	for( i = 0; i < noChecks; i++ )
		{
		const CONTEXT_INFO *contextInfoPtr = callbackArg;

		/* Check whether the abort flag has been set for an async keygen.
		   We do this before the Miller-Rabin check to ensure that it always 
		   gets called at least once for every call to primeProbable() - 
		   since the majority of n values fail the witness() function, 
		   it'd almost never get called after witness() has been called */
		if( contextInfoPtr->flags & CONTEXT_ASYNC_ABORT )
			{
			status = ASYNC_ABORT;
			break;
			}

		/* Instead of using a bignum for the Miller-Rabin check, we use a
		   series of small primes.  The reason for this is that if bases a1
		   and a2 are strong liars for n then their product a1a2 is also very
		   likely to be a strong liar, so using a composite base doesn't give
		   us any great advantage.  In addition an initial test with a=2 is
		   beneficial since most composite numbers will fail Miller-Rabin
		   with a=2, and exponentiation with base 2 is faster than general-
		   purpose exponentiation.  Finally, using small values instead of
		   random bignums is both significantly more efficient and much
		   easier on the RNG.   In theory in order to use the first noChecks 
		   small primes as the base instead of using random bignum bases we 
		   would have to assume that the extended Riemann hypothesis holds 		   
		   (without this, which allows us to use values 1 < check < 
		   2 * log( candidate )^2, we'd have to pick random check values as 
		   required for Monte Carlo algorithms), however the requirement for 
		   random bases assumes that the candidates could be chosen 
		   maliciously to be pseudoprime to any reasonable list of bases, 
		   thus requiring random bases to evade the problem.  Obviously we're 
		   not going to do this, so one base is as good as another, and small 
		   primes work well (even a single Fermat test has a failure 
		   probability of around 10e-44 for 512-bit primes if you're not 
		   trying to cook the primes, this is why Fermat works as a 
		   verification of the Miller-Rabin test in generatePrime()) */
		BN_set_word( a, primes[ i ] );
		status = witness( pkcInfo, a, n, n_1, u, k, &pkcInfo->montCTX1 );
		if( cryptStatusError( status ) )
			return( status );
		if( status )
			return( FALSE );	/* It's not a prime */
		}

	/* It's prime */
	return( TRUE );
	}

/* Generate a prime.  If the exponent is present, this will also verify that
   gcd( (p - 1)(q - 1), exponent ) = 1, which is required for RSA */

static int generatePrime( PKC_INFO *pkcInfo, BIGNUM *candidate, 
						  const int noBits, const long exponent, 
						  const void *callbackArg )
	{
	RESOURCE_DATA msgData;
	const int noChecks = getNoPrimeChecks( noBits );
	BOOLEAN *sieveArray;
	int offset, oldOffset = 0, startPoint, bnStatus = BN_STATUS, status;

	/* Start with a cryptographically strong odd random number ("There is a 
	   divinity in odd numbers", William Shakespeare, "Merry Wives of 
	   Windsor").  We set the two high bits so that (when generating RSA 
	   keys) pq will end up exactly 2n bits long */
	status = generateBignum( candidate, noBits, 0xC0, 0x1 );
	if( cryptStatusError( status ) )
		return( status );

	/* Allocate the array */
	if( ( sieveArray = clAlloc( "generatePrime", \
								SIEVE_SIZE * sizeof( BOOLEAN ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	do
		{
		/* Set up the sieve array for the number and pick a random starting
		   point */
		initSieve( sieveArray, candidate );
		setMessageData( &msgData, &startPoint, sizeof( int ) );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_RANDOM );
		if( cryptStatusError( status ) )
			break;
		startPoint &= SIEVE_SIZE - 1;

		/* Perform a random-probing search for a prime.  Poli, poli, di 
		   umbuendo */
		for( offset = nextEntry( startPoint ); offset != startPoint;
			 offset = nextEntry( offset ) )
			{
#ifdef CHECK_PRIMETEST
			LARGE_INTEGER tStart, tStop;
			BOOLEAN passedFermat, passedOldPrimeTest;
			int oldTicks, newTicks, ratio;
#endif /* CHECK_PRIMETEST */
			long remainder;

			/* If this candidate is divisible by anything, continue */
			if( sieveArray[ offset ] )
				continue;

			/* Adjust the candidate by the number of nonprimes we've
			   skipped */
			if( offset > oldOffset )
				CK( BN_add_word( candidate, ( offset - oldOffset ) * 2 ) );
			else
				CK( BN_sub_word( candidate, ( oldOffset - offset ) * 2 ) );
			oldOffset = offset;

#if defined( CHECK_PRIMETEST )
			/* Perform a Fermat test to the base 2 (Fermat = a^p-1 mod p == 1
			   -> a^p mod p == a, for all a), which isn't as reliable as
			   Miller-Rabin but may be quicker if a fast base 2 modexp is
			   available (currently it provides no improvement at all over the
			   use of straight Miller-Rabin).  Currently it's only used to
			   sanity-check the MR test, but if a faster version is 
			   available, it can be used as a filter to weed out most
			   pseudoprimes */
			CK( BN_MONT_CTX_set( &pkcInfo->montCTX1, candidate, 
								 &pkcInfo->bnCTX ) );
			CK( BN_set_word( &pkcInfo->tmp1, 2 ) );
			CK( BN_mod_exp_mont( &pkcInfo->tmp2, &pkcInfo->tmp1, candidate, 
								 candidate, &pkcInfo->bnCTX,
								 &pkcInfo->montCTX1 ) );
			passedFermat = ( bnStatusOK( bnStatus ) && \
						     BN_is_word( &pkcInfo->tmp2, 2 ) ) ? TRUE : FALSE;

			/* Perform the older probabalistic test */
			QueryPerformanceCounter( &tStart );
			status = primeProbableOld( pkcInfo, candidate, noChecks, 
									   callbackArg );
			QueryPerformanceCounter( &tStop );
			assert( tStart.HighPart == tStop.HighPart );
			oldTicks = tStop.LowPart - tStart.LowPart;
			if( cryptStatusError( status ) )
				break;
			passedOldPrimeTest = status;

			/* Perform the probabalistic test */
			QueryPerformanceCounter( &tStart );
			status = primeProbable( pkcInfo, candidate, noChecks, 
									callbackArg );
			QueryPerformanceCounter( &tStop );
			assert( tStart.HighPart == tStop.HighPart );
			newTicks = tStop.LowPart - tStart.LowPart;
			ratio = ( oldTicks * 100 ) / newTicks;
			printf( "%4d bits, old MR = %6d ticks, new MR = %6d ticks, "
					"ratio = %d.%d\n", noBits, oldTicks, newTicks, 
					ratio / 100, ratio % 100 );
			if( status != passedFermat || status != passedOldPrimeTest )
				{
				printf( "Fermat reports %d, old Miller-Rabin reports %d, "
						"new Miller-Rabin reports %d.\n", 
						passedFermat, passedOldPrimeTest, status );
				getchar();
				}
#else
			status = primeProbable( pkcInfo, candidate, noChecks, 
									callbackArg );
#endif /* CHECK_PRIMETEST */
			if( cryptStatusError( status ) )
				break;
			if( !status )
				continue;

			/* If it's not for RSA use, we've found our candidate */
			if( exponent != CRYPT_UNUSED )
				break;

			/* It's for use with RSA, check the RSA condition that
			   gcd( p - 1, exp ) == 1.  Since exp is a small prime, we can do
			   this efficiently by checking that ( p - 1 ) mod exp != 0 */
			CK( BN_sub_word( candidate, 1 ) );
			remainder = BN_mod_word( candidate, exponent );
			CK( BN_add_word( candidate, 1 ) );
			if( bnStatusOK( bnStatus ) && remainder )
				break;	/* status = TRUE from above */
			}
		}
	while( status == FALSE );	/* -ve = error, TRUE = success */

	/* Clean up */
	zeroise( sieveArray, SIEVE_SIZE * sizeof( BOOLEAN ) );
	clFree( "generatePrime", sieveArray );
	return( ( status == TRUE ) ? CRYPT_OK : status );
	}

/****************************************************************************
*																			*
*							Generate an RSA Key								*
*																			*
****************************************************************************/

/* We use F4 as the default public exponent e unless the user chooses to 
   override this with some other value.  The older (X.509v1) recommended 
   value of 3 is insecure for general use and more recent work indicates that 
   values like 17 (used by PGP) are also insecure against the Hastad attack.  
   We could work around this by using 41 or 257 as the exponent, however 
   current best practice favours F4 unless you're doing banking standards, in
   which case you set e=2 (EMV) and use raw, unpadded RSA (HBCI) to make it 
   easier for students to break your banking security as a homework exercise */

#ifndef RSA_PUBLIC_EXPONENT
  #define RSA_PUBLIC_EXPONENT		65537L
#endif /* RSA_PUBLIC_EXPONENT */

/* Adjust p and q if necessary to ensure that the CRT decrypt works */

static int fixCRTvalues( PKC_INFO *pkcInfo, const BOOLEAN fixPKCSvalues )
	{
	BIGNUM *p = &pkcInfo->rsaParam_p, *q = &pkcInfo->rsaParam_q;

	/* Make sure that p > q, which is required for the CRT decrypt */
	if( BN_cmp( p, q ) >= 0 )
		return( CRYPT_OK );

	/* Swap the values p and q and, if necessary, the PKCS parameters e1
	   and e2 that depend on them (e1 = d mod (p - 1) and 
	   e2 = d mod (q - 1)), and recompute u = qInv mod p */
	BN_swap( p, q );
	if( !fixPKCSvalues )
		return( CRYPT_OK );
	BN_swap( &pkcInfo->rsaParam_exponent1, &pkcInfo->rsaParam_exponent2 );
	return( BN_mod_inverse( &pkcInfo->rsaParam_u, q, p, 
							&pkcInfo->bnCTX ) != NULL ? \
			CRYPT_OK : CRYPT_ERROR_FAILED );
	}

/* Evaluate the Montgomery forms for public and private components */

static int getRSAMontgomery( PKC_INFO *pkcInfo, const BOOLEAN isPublicKey )
	{
	/* Evaluate the public value */
	if( !BN_MONT_CTX_set( &pkcInfo->rsaParam_mont_n, &pkcInfo->rsaParam_n, 
						  &pkcInfo->bnCTX ) )
		return( CRYPT_ERROR_FAILED );
	if( isPublicKey )
		return( CRYPT_OK );

	/* Evaluate the private values */
	return( BN_MONT_CTX_set( &pkcInfo->rsaParam_mont_p, &pkcInfo->rsaParam_p, 
							 &pkcInfo->bnCTX ) && \
			BN_MONT_CTX_set( &pkcInfo->rsaParam_mont_q, &pkcInfo->rsaParam_q, 
							 &pkcInfo->bnCTX ) ? \
			CRYPT_OK : CRYPT_ERROR_FAILED );
	}

/* Generate an RSA key pair into an encryption context */

int generateRSAkey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BIGNUM *d = &pkcInfo->rsaParam_d, *p = &pkcInfo->rsaParam_p;
	BIGNUM *q = &pkcInfo->rsaParam_q;
	BIGNUM *tmp = &pkcInfo->tmp1;
	int pBits, qBits, bnStatus = BN_STATUS, status;

	/* Determine how many bits to give to each of p and q */
	pBits = ( keySizeBits + 1 ) / 2;
	qBits = keySizeBits - pBits;
	pkcInfo->keySizeBits = pBits + qBits;

	/* Generate the primes p and q and set them up so that the CRT decrypt 
	   will work */
	BN_set_word( &pkcInfo->rsaParam_e, RSA_PUBLIC_EXPONENT );
	status = generatePrime( pkcInfo, p, pBits, RSA_PUBLIC_EXPONENT, 
							contextInfoPtr );
	if( cryptStatusOK( status ) )
		status = generatePrime( pkcInfo, q, qBits, RSA_PUBLIC_EXPONENT, 
								contextInfoPtr );
	if( cryptStatusOK( status ) )
		status = fixCRTvalues( pkcInfo, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Compute d = eInv mod (p - 1)(q - 1), e1 = d mod (p - 1), and
	   e2 = d mod (q - 1) */
	CK( BN_sub_word( p, 1 ) );
	CK( BN_sub_word( q, 1 ) );
	CK( BN_mul( tmp, p, q, &pkcInfo->bnCTX ) );
	CKPTR( BN_mod_inverse( d, &pkcInfo->rsaParam_e, tmp, &pkcInfo->bnCTX ) );
	CK( BN_mod( &pkcInfo->rsaParam_exponent1, d,
				p, &pkcInfo->bnCTX ) );
	CK( BN_mod( &pkcInfo->rsaParam_exponent2, d, q, &pkcInfo->bnCTX ) );
	CK( BN_add_word( p, 1 ) );
	CK( BN_add_word( q, 1 ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Compute n = pq, and u = qInv mod p */
	CK( BN_mul( &pkcInfo->rsaParam_n, p, q, &pkcInfo->bnCTX ) );
	CKPTR( BN_mod_inverse( &pkcInfo->rsaParam_u, q, p, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Evaluate the Montgomery forms */
	return( getRSAMontgomery( pkcInfo, FALSE ) );
	}

/****************************************************************************
*																			*
*							Initialise/Check an RSA Key						*
*																			*
****************************************************************************/

/* Perform validity checks on the private key.  We have to make the PKC_INFO
   data non-const because the bignum code wants to modify some of the values 
   as it's working with them */

static BOOLEAN checkRSAPrivateKeyComponents( PKC_INFO *pkcInfo )
	{
	BIGNUM *n = &pkcInfo->rsaParam_n, *e = &pkcInfo->rsaParam_e;
	BIGNUM *d = &pkcInfo->rsaParam_d, *p = &pkcInfo->rsaParam_p;
	BIGNUM *q = &pkcInfo->rsaParam_q;
	BIGNUM *p1 = &pkcInfo->tmp1, *q1 = &pkcInfo->tmp2, *tmp = &pkcInfo->tmp3;
	const BN_ULONG eWord = BN_get_word( e );
	int bnStatus = BN_STATUS;

	/* We don't allow bignum e values, both because it doesn't make sense to
	   use them and because the tests below assume that e will fit into a
	   machine word */
	if( eWord == BN_MASK2 )
		return( FALSE );

	CKPTR( BN_copy( p1, p ) );
	CK( BN_sub_word( p1, 1 ) );
	CKPTR( BN_copy( q1, q ) );
	CK( BN_sub_word( q1, 1 ) );
	if( bnStatusError( bnStatus ) )
		return( FALSE );

	/* Verify that n = p * q */
	CK( BN_mul( tmp, p, q, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) || BN_cmp( n, tmp ) != 0 )
		return( FALSE );

	/* Verify that ( d * e ) mod p-1 == 1 and ( d * e ) mod q-1 == 1.  Some
	   implementations don't store d since it's not needed when the CRT
	   shortcut is used, so we can only perform this check if d is present */
	if( !BN_is_zero( d ) )
		{
		CK( BN_mod_mul( tmp, d, e, p1, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) || !BN_is_one( tmp ) )
			return( FALSE );
		CK( BN_mod_mul( tmp, d, e, q1, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) || !BN_is_one( tmp ) )
			return( FALSE );
		}

	/* Verify that ( q * u ) mod p == 1 */
	CK( BN_mod_mul( tmp, q, &pkcInfo->rsaParam_u, p, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) || !BN_is_one( tmp ) )
		return( FALSE );

	/* Verify that e is a small prime.  The easiest way to do this would be
	   to compare it to a set of standard values, but there'll always be some
	   wierdo implementation that uses a nonstandard value and that would
	   therefore fail the test, so we perform a quick check that just tries
	   dividing by all primes below 1000.  In addition since in almost all
	   cases e will be one of a standard set of values, we don't bother with
	   the trial division unless it's an unusual value.  This test isn't
	   perfect, but it'll catch obvious non-primes.

	   Note that OpenSSH hardcodes e = 35, which is both a suboptimal
	   exponent (it's less efficient that a safer value like 257 or F4)
	   and non-prime.  The reason for this was that the original SSH used an
	   e relatively prime to (p-1)(q-1), choosing odd (in both senses of the 
	   word) numbers > 31.  33 or 35 probably ended up being chosen 
	   frequently, so it was hardcoded into OpenSSH.  In order to use 
	   OpenSSH keys, you need to comment out this test and the following 
	   one */
	if( eWord != 3 && eWord != 17 && eWord != 257 && eWord != 65537L )
		{
		static const FAR_BSS unsigned int smallPrimes[] = {
			   2,   3,   5,   7,  11,  13,  17,  19,
			  23,  29,  31,  37,  41,  43,  47,  53,
			  59,  61,  67,  71,  73,  79,  83,  89,
			  97, 101, 103, 107, 109, 113, 127, 131,
			 137, 139, 149, 151, 157, 163, 167, 173,
			 179, 181, 191, 193, 197, 199, 211, 223,
			 227, 229, 233, 239, 241, 251, 257, 263,
			 269, 271, 277, 281, 283, 293, 307, 311,
			 313, 317, 331, 337, 347, 349, 353, 359,
			 367, 373, 379, 383, 389, 397, 401, 409,
			 419, 421, 431, 433, 439, 443, 449, 457,
			 461, 463, 467, 479, 487, 491, 499, 503,
			 509, 521, 523, 541, 547, 557, 563, 569,
			 571, 577, 587, 593, 599, 601, 607, 613,
			 617, 619, 631, 641, 643, 647, 653, 659,
			 661, 673, 677, 683, 691, 701, 709, 719,
			 727, 733, 739, 743, 751, 757, 761, 769,
			 773, 787, 797, 809, 811, 821, 823, 827,
			 829, 839, 853, 857, 859, 863, 877, 881,
			 883, 887, 907, 911, 919, 929, 937, 941,
			 947, 953, 967, 971, 977, 983, 991, 997,
			 0
			 };
		int i;

		for( i = 0; smallPrimes[ i ] != 0; i++ )
			if( eWord % smallPrimes[ i ] == 0 )
				return( FALSE );
		}

	/* Verify that gcd( ( p - 1 )( q - 1), e ) == 1.  Since e is a small
	   prime, we can do this much more efficiently by checking that
	   ( p - 1 ) mod e != 0 and ( q - 1 ) mod e != 0 */
	if( BN_mod_word( p1, eWord ) == 0 || BN_mod_word( q1, eWord ) == 0 )
		return( FALSE );

	return( TRUE );
	}

/* Initialise and check an RSA key.  Unlike the DLP check, this function 
   combines the initialisation with the checking, since the two are deeply
   intertwingled */

int initCheckRSAkey( CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BIGNUM *n = &pkcInfo->rsaParam_n, *e = &pkcInfo->rsaParam_e;
	BIGNUM *d = &pkcInfo->rsaParam_d, *p = &pkcInfo->rsaParam_p;
	BIGNUM *q = &pkcInfo->rsaParam_q;
	int bnStatus = BN_STATUS, status = CRYPT_OK;

	/* Make sure that the necessary key parameters have been initialised */
	if( BN_is_zero( n ) || BN_is_zero( e ) )
		return( CRYPT_ARGERROR_STR1 );
	if( !( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		if( BN_is_zero( p ) || BN_is_zero( q ) )
			return( CRYPT_ARGERROR_STR1 );
		if( BN_is_zero( d ) && \
			( BN_is_zero( &pkcInfo->rsaParam_exponent1 ) || \
			  BN_is_zero( &pkcInfo->rsaParam_exponent2 ) ) )
			/* Either d or e1 et al must be present, d isn't needed if we
			   have e1 et al and e1 et al can be reconstructed from d */
			return( CRYPT_ARGERROR_STR1 );
		}

	/* Make sure that the key paramters are valid: n > MIN_PKCSIZE_BITS, 
	   e >= 3, |p-q| > 128 bits */
	if( BN_num_bits( n ) <= MIN_PKCSIZE_BITS || BN_get_word( e ) < 3 )
		return( CRYPT_ARGERROR_STR1 );
	if( !( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		/* Make sure that p and q differ by at least 128 bits */
		CKPTR( BN_copy( &pkcInfo->tmp1, p ) );
		CK( BN_sub( &pkcInfo->tmp1, &pkcInfo->tmp1, q ) );
		if( bnStatusError( bnStatus ) || BN_num_bits( &pkcInfo->tmp1 ) < 128 )
			return( CRYPT_ARGERROR_STR1 );
		}

	/* If we're not using PKCS keys that have exponent1 = d mod ( p - 1 )
	   and exponent2 = d mod ( q - 1 ) precalculated, evaluate them now.
	   If there's no u precalculated, evaluate it now */
	if( !( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		if( BN_is_zero( &pkcInfo->rsaParam_exponent1 ) )
			{
			BIGNUM *exponent1 = &pkcInfo->rsaParam_exponent1;
			BIGNUM *exponent2 = &pkcInfo->rsaParam_exponent2;

			CKPTR( BN_copy( exponent1, p ) );/* exponent1 = d mod ( p - 1 ) ) */
			CK( BN_sub_word( exponent1, 1 ) );
			CK( BN_mod( exponent1, d, exponent1, &pkcInfo->bnCTX ) );
			CKPTR( BN_copy( exponent2, q ) );/* exponent2 = d mod ( q - 1 ) ) */
			CK( BN_sub_word( exponent2, 1 ) );
			CK( BN_mod( exponent2, d, exponent2, &pkcInfo->bnCTX ) );
			if( bnStatusError( bnStatus ) )
				return( getBnStatus( bnStatus ) );
			}
		if( BN_is_zero( &pkcInfo->rsaParam_u ) )
			{
			CKPTR( BN_mod_inverse( &pkcInfo->rsaParam_u, q, p, 
								   &pkcInfo->bnCTX ) );
			if( bnStatusError( bnStatus ) )
				return( getBnStatus( bnStatus ) );
			}
		}

	/* Make sure that p and q are set up correctly for the CRT decryption and
	   precompute the Montgomery forms */
	if( !( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		status = fixCRTvalues( pkcInfo, TRUE );
	if( cryptStatusOK( status ) )
		status = getRSAMontgomery( pkcInfo, 
							( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) ? \
							TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Now that we've got the various other values set up, perform further
	   validity checks on the private key */
	if( !( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) && \
		!checkRSAPrivateKeyComponents( pkcInfo ) )
		return( CRYPT_ARGERROR_STR1 );

	pkcInfo->keySizeBits = BN_num_bits( &pkcInfo->rsaParam_n );

	/* Finally, if we're using blinding, calculate the initial blinding 
	   values */
	if( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION )
		{
		BIGNUM *k = &pkcInfo->rsaParam_blind_k;
		BIGNUM *kInv = &pkcInfo->rsaParam_blind_kInv;
		RESOURCE_DATA msgData;
		BYTE buffer[ CRYPT_MAX_PKCSIZE ];
		int noBytes = bitsToBytes( pkcInfo->keySizeBits );

		/* Generate a random bignum.  Since this merely has to be 
		   unpredictable to an outsider but not cryptographically strong,
		   and to avoid having more crypto RNG output than necessary sitting 
		   around in memory, we get it from the nonce PRNG rather than the 
		   crypto one */
		setMessageData( &msgData, buffer, noBytes );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusOK( status ) )
			{
			buffer[ 0 ] &= 255 >> ( -pkcInfo->keySizeBits & 7 );
			status = ( BN_bin2bn( buffer, noBytes, k ) == NULL ) ? \
					 CRYPT_ERROR_MEMORY : CRYPT_OK;
			}
		zeroise( buffer, noBytes );
		if( cryptStatusError( status ) )
			return( status );

		/* Set up the blinding and unblinding values */
		CK( BN_mod( k, k, n, &pkcInfo->bnCTX ) );	/* k = rand() mod n */
		CKPTR( BN_mod_inverse( kInv, k, n, &pkcInfo->bnCTX ) );
													/* kInv = k^-1 mod n */
		CK( BN_mod_exp_mont( k, k, e, n, &pkcInfo->bnCTX, 
							 &pkcInfo->rsaParam_mont_n ) );
													/* k = k^e mod n */
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		}

	return( status );
	}

/****************************************************************************
*																			*
*			  					Generate DL Primes							*
*							Copyright Kevin J Bluck 1998					*
*						 Copyright Peter Gutmann 1998-2002					*
*																			*
****************************************************************************/

/* DLP-based PKCs have various requirements for the generated parameters:

	DSA: p, q, and g of preset lengths (currently p isn't fixed at exactly
		n * 64 bits because of the way the Lim-Lee algorithm works, it's
		possible to get this by iterating the multiplication step until the
		result is exactly n * 64 bits but this doesn't seem worth the
		effort), x = 1...q-1.
	PKCS #3 DH: No g (it's fixed at 2) or q.  This is "real" DH (rather than
		the DSA-hack version) but doesn't seem to be used by anything.  Keys
		of this type can be generated if required, but the current code is
		configured to always generate X9.42 DH keys.
	X9.42 DH: p, q, and g as for DSA but without the 160-bit SHA-enforced
		upper limit on q so that p can go above 1024 bits, x = 2...q-2.
	Elgamal: As X9.42 DH */

/* The maximum number of factors required to generate a prime using the Lim-
   Lee algorithm.  The value 160 is the minimum safe exponent size */

#define MAX_NO_FACTORS	( ( MAX_PKCSIZE_BITS / 160 ) + 1 )

/* The maximum number of small primes required to generate a prime using the
   Lim-Lee algorithm.  There's no fixed bound on this value, but in the worst
   case we start with ~ 4096 / getDLPexpSize( 4096 ) primes = ~ 13 values,
   and add one more prime on each retry.  Typically we need 10-15 for keys
   in the most commonly-used range 512-2048 bits.  In order to simplify the 
   handling of values, we allow for 128 primes, which has a vanishingly small 
   probability of failing and also provides a safe upper bound for the
   number of retries (there's something wrong with the algorithm if it 
   requires anything near this many retries) */

#define MAX_NO_PRIMES	128

/* Select a generator g for the prime moduli p and q.  g will be chosen so
   that it is of prime order q, where q divides (p - 1), i.e. g generates 
   the subgroup of order q in the multiplicative group of GF(p) 
   (traditionally for PKCS #3 DH g is fixed at 2, which is safe even when 
   it's not a primitive root since it still covers half of the space of 
   possible residues, however we always generate a FIPS 186-style g value) */

static int findGeneratorForPQ( PKC_INFO *pkcInfo )
	{
	BIGNUM *p = &pkcInfo->dlpParam_p, *q = &pkcInfo->dlpParam_q;
	BIGNUM *g = &pkcInfo->dlpParam_g;
	BIGNUM *j = &pkcInfo->tmp1, *gCounter = &pkcInfo->tmp2;
	int bnStatus = BN_STATUS;

	/* j = (p - 1) / q */
	CK( BN_sub_word( p, 1 ) );
	CK( BN_div( j, NULL, p, q, &pkcInfo->bnCTX ) );
	CK( BN_add_word( p, 1 ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Starting gCount at 3, set g = (gCount ^ j) mod p until g != 1.
	   Although FIPS 196/X9.30/X9.42 merely require that 1 < g < p-1, if we
	   use small integers it makes this operation much faster.  Note that 
	   we can't use a Montgomery modexp at this point since we haven't
	   evaluated the Montgomery form of p yet */
	CK( BN_set_word( gCounter, 2 ) );
	do
		{
		CK( BN_add_word( gCounter, 1 ) );
		CK( BN_mod_exp( g, gCounter, j, p, &pkcInfo->bnCTX ) );
		}
	while( bnStatusOK( bnStatus ) && BN_is_one( g ) );

	return( getBnStatus( bnStatus ) );
	}

/* Generate prime numbers for DLP-based PKC's using the Lim-Lee algorithm:

	p = 2 * q * ( prime[1] * ... prime[n] ) + 1 */

static int generateDLPublicValues( PKC_INFO *pkcInfo, const int pBits, 
								   int qBits, void *callBackArg )
	{
	const int safeExpSizeBits = getDLPexpSize( pBits );
	const int noChecks = getNoPrimeChecks( pBits );
	BIGNUM llPrimes[ MAX_NO_PRIMES ], llProducts[ MAX_NO_FACTORS ];
	BIGNUM *p = &pkcInfo->dlpParam_p, *q = &pkcInfo->dlpParam_q;
	BOOLEAN primeFound = FALSE;
	int indices[ MAX_NO_FACTORS ];
	int nPrimes, nFactors, factorBits, i, bnStatus = BN_STATUS, status;

	assert( p != NULL );
	assert( pBits >= 512 && pBits <= MAX_PKCSIZE_BITS );
	assert( q != NULL );
	assert( ( qBits >= 160 && qBits <= MAX_PKCSIZE_BITS ) || \
			qBits == CRYPT_USE_DEFAULT );
	assert( callBackArg != NULL );
	assert( getDLPexpSize( 512 ) == 160 );
	assert( getDLPexpSize( 1024 ) == 169 );
	assert( getDLPexpSize( 1536 ) == 198 );
	assert( getDLPexpSize( 2048 ) == 225 );
	assert( getDLPexpSize( 3072 ) == 270 );
	assert( getDLPexpSize( 4096 ) == 305 );

	/* If the caller doesn't require a fixed-size q, use the minimum safe
	   exponent size */
	if( qBits == CRYPT_USE_DEFAULT )
		qBits = safeExpSizeBits;

	/* Determine how many factors we need and the size in bits of the 
	   factors */
	factorBits = ( pBits - qBits ) - 1;
	nFactors = nPrimes = ( factorBits / safeExpSizeBits ) + 1;
	factorBits /= nFactors;

	/* Generate a random prime q and multiply by 2 to form the base for the
	   other factors */
	status = generatePrime( pkcInfo, q, qBits, CRYPT_UNUSED, callBackArg );
	if( cryptStatusError( status ) )
		return( status );
	BN_lshift1( q, q );

	/* Set up the permutation control arrays and generate the first nFactors 
	   factors */
	for( i = 0; i < MAX_NO_FACTORS; i++ )
		BN_init( &llProducts[ i ] );
	for( i = 0; i < MAX_NO_PRIMES; i++ )
		BN_init( &llPrimes[ i ] );
	for( i = 0; i < nFactors; i++ )
		{
		status = generatePrime( pkcInfo, &llPrimes[ i ], factorBits, 
								CRYPT_UNUSED, callBackArg );
		if( cryptStatusError( status ) )
			goto cleanup;
		}

	do
		{
		int indexMoved;

		/* Initialize the indices for the permutation.  We try the first 
		   nFactors factors first, since any new primes are added at the end */
		indices[ nFactors - 1 ] = nPrimes - 1;
		for( i = nFactors - 2; i >= 0; i-- )
			indices[ i ] = indices[ i + 1 ] - 1;
		BN_mul( &llProducts[ nFactors - 1 ], q, &llPrimes[ nPrimes - 1 ], 
				&pkcInfo->bnCTX );
		indexMoved = nFactors - 2;

		/* Test all possible new prime permutations until a prime is found or 
		   we run out of permutations */
		do
			{
			/* Assemble a new candidate prime 2 * q * primes + 1 from the 
			   currently indexed random primes */
			for( i = indexMoved; i >= 0; i-- )
				CK( BN_mul( &llProducts[ i ], &llProducts[ i + 1 ],
							&llPrimes[ indices[ i ] ], &pkcInfo->bnCTX ) );
			CKPTR( BN_copy( p, &llProducts[ 0 ] ) );
			CK( BN_add_word( p, 1 ) );
			if( bnStatusError( bnStatus ) )
				{
				status = getBnStatus( bnStatus );
				goto cleanup;
				}

			/* If the candidate has a good chance of being prime, try a
			   probabilistic test and exit if it succeeds */
			if( primeSieve( p ) )
				{
				status = primeProbable( pkcInfo, p, noChecks, callBackArg );
				if( cryptStatusError( status ) )
					goto cleanup;
				if( status )
					{
					primeFound = TRUE;
					break;
					}
				}

			/* Find the lowest index which is not already at the lowest 
			   possible point and move it down one */
			for( i = 0; i < nFactors; i++ )
				if( indices[ i ] > i )
					{
					indices[ i ]--;
					indexMoved = i;
					break;
					}

			/* If we moved down the highest index, we've exhausted all the 
			   permutations so we have to start over with another prime */
			if( ( indexMoved == nFactors - 1 ) || ( i >= nFactors ) )
				break;

			/* We haven't changed the highest index, take all the indices 
			   below the one we moved down and move them up so they're packed 
			   up as high as they'll go */
			for( i = indexMoved - 1; i >= 0; i-- )
				indices[ i ] = indices[ i + 1 ] - 1;
			} 
		while( indices[ nFactors - 1 ] > 0 );

		/* If we haven't found a prime yet, add a new prime to the pool and
		   try again */
		if( !primeFound )
			{
			if( nPrimes >= MAX_NO_PRIMES )
				{
				/* We've run through an extraordinary number of primes, 
				   something is wrong */
				assert( NOTREACHED );
				status = CRYPT_ERROR_FAILED;
				goto cleanup;
				}
			status = generatePrime( pkcInfo, &llPrimes[ nPrimes++ ], factorBits, 
									CRYPT_UNUSED, callBackArg );
			if( cryptStatusError( status ) )
				goto cleanup;
			}
		}
	while( !primeFound );

	/* Recover the original value of q by dividing by 2 and find a generator 
	   suitable for p and q */
	BN_rshift1( q, q );
	status = findGeneratorForPQ( pkcInfo );

cleanup:

	/* Free the local storage */
	for( i = 0; i < nPrimes; i++ )
		BN_clear_free( &llPrimes[ i ] );
	for( i = 0; i < nFactors; i++ )
		BN_clear_free( &llProducts[ i ] );
	zeroise( llPrimes, sizeof( BIGNUM ) * MAX_NO_PRIMES );
	zeroise( llProducts, sizeof( BIGNUM ) * MAX_NO_FACTORS );

	return( status );
	}

/* Generate the DLP private value x */

static int generateDLPrivateValue( PKC_INFO *pkcInfo )
	{
	BIGNUM *x = &pkcInfo->dlpParam_x, *q = &pkcInfo->dlpParam_q; 
	const int qBits = BN_num_bits( q );
	int bnStatus = BN_STATUS, status;

	/* If it's a PKCS #3 DH key, there won't be a q value present, so we have
	   to estimate the appropriate x size in the same way that we estimated
	   the q size when we generated the public key components */
	if( BN_is_zero( q ) )
		return( generateBignum( x, 
					getDLPexpSize( BN_num_bits( &pkcInfo->dlpParam_p ) ),
					0xC0, 0 ) );

	/* Generate the DLP private value x s.t. 2 <= x <= q-2 (this is the
	   lowest common denominator of FIPS 186's 1...q-1 and X9.42's 2...q-2).
	   Because the mod q-2 is expensive we do a quick check to make sure it's
	   really necessary before calling it */
	status = generateBignum( x, qBits, 0xC0, 0 );
	if( cryptStatusError( status ) )
		return( status );
	CK( BN_sub_word( q, 2 ) );
	if( BN_cmp( x, q ) > 0 )
		{
		/* Trim x down to size.  Actually we get the upper bound as q-3,
		   but over a 160-bit (minimum) number range this doesn't matter */
		CK( BN_mod( x, x, q, &pkcInfo->bnCTX ) );

		/* If the value we ended up with is too small, just generate a new
		   value one bit shorter, which guarantees that it'll fit the 
		   criteria (the target is a suitably large random value value, not 
		   the closest possible fit within the range) */
		if( bnStatusOK( bnStatus ) && BN_num_bits( x ) < qBits - 5 )
			status = generateBignum( x, qBits - 1, 0xC0, 0 );
		}
	CK( BN_add_word( q, 2 ) );

	return( cryptStatusError( status ) ? status : getBnStatus( bnStatus ) );
	}

/* Generate a generic DLP key */

int generateDLPkey( CONTEXT_INFO *contextInfoPtr, const int keyBits,
					const int qBits, const BOOLEAN generateDomainParameters )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	int bnStatus = BN_STATUS, status;

	/* Generate the domain parameters if necessary */
	if( generateDomainParameters )
		{
		pkcInfo->keySizeBits = keyBits;
		status = generateDLPublicValues( pkcInfo, keyBits, qBits, contextInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Generate the private key */
	assert( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
			!BN_is_zero( &pkcInfo->dlpParam_q ) );
	status = generateDLPrivateValue( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Evaluate the Montgomery forms and calculate y */
	BN_MONT_CTX_init( &pkcInfo->dlpParam_mont_p );
	CK( BN_MONT_CTX_set( &pkcInfo->dlpParam_mont_p, &pkcInfo->dlpParam_p, 
						 &pkcInfo->bnCTX ) );
	if( bnStatusOK( bnStatus ) )
		CK( BN_mod_exp_mont( &pkcInfo->dlpParam_y, &pkcInfo->dlpParam_g,
							 &pkcInfo->dlpParam_x, &pkcInfo->dlpParam_p, 
							 &pkcInfo->bnCTX, &pkcInfo->dlpParam_mont_p ) );
	return( getBnStatus( bnStatus ) );
	}

/****************************************************************************
*																			*
*							Initialise/Check a DLP Key						*
*																			*
****************************************************************************/

/* Check DLP parameters when loading a key.  We have to make the PKC_INFO
   data non-const because the bignum code wants to modify some of the values 
   as it's working with them */

int checkDLPkey( const CONTEXT_INFO *contextInfoPtr, const BOOLEAN isPKCS3 )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BIGNUM *p = &pkcInfo->dlpParam_p, *g = &pkcInfo->dlpParam_g;
	BIGNUM *tmp = &pkcInfo->tmp1;
	int bnStatus = BN_STATUS;

	/* Make sure that the necessary key parameters have been initialised.  
	   Since PKCS #3 doesn't use the q parameter, we only require it for 
	   algorithms that specifically use FIPS 186 values */
	if( BN_is_zero( p ) || BN_is_zero( g ) || \
		BN_is_zero( &pkcInfo->dlpParam_y ) || \
		( !( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) && \
		  BN_is_zero( &pkcInfo->dlpParam_x ) ) )
		return( CRYPT_ARGERROR_STR1 );
	if( !isPKCS3 && BN_is_zero( &pkcInfo->dlpParam_q ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Make sure that the key paramters are valid: p > MIN_PKCSIZE_BITS 
	   (nominally 512 bits), 2 <= g <= p-2, and g a generator of order q if 
	   the q parameter is present (i.e. it's a non-PKCS #3 key) */
	if( BN_num_bits( p ) < MIN_PKCSIZE_BITS || BN_num_bits( g ) < 2 )
		return( CRYPT_ARGERROR_STR1 );
	CKPTR( BN_copy( tmp, p ) );
	CK( BN_sub_word( tmp, 1 ) );
	if( bnStatusError( bnStatus ) || BN_cmp( g, tmp ) >= 0 )
		return( CRYPT_ARGERROR_STR1 );
	if( !isPKCS3 )
		{
		CK( BN_mod_exp_mont( tmp, g, &pkcInfo->dlpParam_q, p, &pkcInfo->bnCTX,
							 &pkcInfo->dlpParam_mont_p ) );
		if( bnStatusError( bnStatus ) || !BN_is_one( tmp ) )
			return( CRYPT_ARGERROR_STR1 );
		}

	/* Make sure that the private key value is valid */
	if( !( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		CK( BN_mod_exp_mont( tmp, g, &pkcInfo->dlpParam_x, p, &pkcInfo->bnCTX,
							 &pkcInfo->dlpParam_mont_p ) );
		if( bnStatusError( bnStatus ) || BN_cmp( tmp, &pkcInfo->dlpParam_y ) )
			return( CRYPT_ARGERROR_STR1 );
		}

	return( CRYPT_OK );
	}

/* Initialise a DLP key */

int initDLPkey( CONTEXT_INFO *contextInfoPtr, const BOOLEAN isDH )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BIGNUM *p = &pkcInfo->dlpParam_p, *g = &pkcInfo->dlpParam_g;
	BIGNUM *x = &pkcInfo->dlpParam_x;
	int bnStatus = BN_STATUS;

	/* If it's a DH key and there's no x value present, generate one 
	   implicitly.  This is needed because all DH keys are effectively 
	   private keys.  We also update the context flags to reflect the
	   change in status */
	if( isDH && BN_is_zero( x ) )
		{
		int status;

		status = generateDLPkey( contextInfoPtr, CRYPT_UNUSED, CRYPT_UNUSED,
								 FALSE );
		if( cryptStatusError( status ) )
			return( status );
		contextInfoPtr->flags &= ~CONTEXT_ISPUBLICKEY;
		contextInfoPtr->flags |= CONTEXT_ISPRIVATEKEY;
		}

	/* Some sources (specifically PKCS #11) don't make y available for
	   private keys, so if the caller is trying to load a private key with a
	   zero y value, we calculate it for them.  First, we check to make sure
	   that we have the values available to calculate y.  We calculate y 
	   itself once we have the Montogomery form of p set up */
	if( BN_is_zero( &pkcInfo->dlpParam_y ) && \
		( BN_is_zero( p ) || BN_is_zero( g ) || BN_is_zero( x ) ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Evaluate the Montgomery form and calculate y if necessary */
	BN_MONT_CTX_init( &pkcInfo->dlpParam_mont_p );
	CK( BN_MONT_CTX_set( &pkcInfo->dlpParam_mont_p, p, &pkcInfo->bnCTX ) );
	if( bnStatusOK( bnStatus ) && BN_is_zero( &pkcInfo->dlpParam_y ) )
		CK( BN_mod_exp_mont( &pkcInfo->dlpParam_y, g, x, p, &pkcInfo->bnCTX, 
							 &pkcInfo->dlpParam_mont_p ) );

	pkcInfo->keySizeBits = BN_num_bits( p );
	return( getBnStatus( bnStatus ) );
	}
