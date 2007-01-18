/****************************************************************************
*																			*
*					cryptlib Prime Generation/Checking Routines				*
*						Copyright Peter Gutmann 1997-2004					*
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

#define PKC_CONTEXT		/* Indicate that we're working with PKC context */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "keygen.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "context/keygen.h"
#endif /* Compiler-specific includes */
#if defined( INC_ALL )
  #include "bn_prime.h"
#else
  #include "bn/bn_prime.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Fast Prime Sieve							*
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
			if( sieveIndex > 0 )
				sieveIndex = ( ( step * 2 ) - sieveIndex ) / 2;

		/* Mark each multiple of the divisor as being divisible */
		while( sieveIndex >= 0 && sieveIndex < SIEVE_SIZE )
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

BOOLEAN primeSieve( const BIGNUM *candidate )
	{
	int i;

	for( i = 1; i < FAST_SIEVE_NUMPRIMES; i++ )
		if( BN_mod_word( candidate, primes[ i ] ) == 0 )
			return( FALSE );

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Generate a Prime Number							*
*																			*
****************************************************************************/

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
	BN_CTX *ctx = pkcInfo->bnCTX;
	BIGNUM *mont_a = &ctx->bn[ ctx->tos++ ];
	const int k = BN_num_bits( n1 );
	int i, bnStatus = BN_STATUS;

	/* All values are manipulated in their Montgomery form, so before we 
	   begin we have to convert a to this form as well */
	if( !BN_to_montgomery( mont_a, a, montCTX_n, pkcInfo->bnCTX ) )
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
								   pkcInfo->bnCTX ) );
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
									   pkcInfo->bnCTX ) );
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
	CK( BN_MONT_CTX_set( montCTX_candidate, candidate, pkcInfo->bnCTX ) );
	CK( BN_to_montgomery( mont_1, BN_value_one(), montCTX_candidate, 
						  pkcInfo->bnCTX ) );
	CKPTR( BN_copy( candidate_1, candidate ) );
	CK( BN_sub_word( candidate_1, 1 ) );
	CK( BN_to_montgomery( mont_candidate_1, candidate_1, montCTX_candidate, 
						  pkcInfo->bnCTX ) );
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
	CK( BN_mod_exp_mont( a, a, u, n, pkcInfo->bnCTX, montCTX_n ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	if( BN_is_one( a ) || !BN_cmp( a, n_1 ) )
		return( FALSE );	/* Probably prime */

	for( i = 1; i < k; i++ )
		{
		/* x(i) = x(i-1)^2 mod n */
		CK( BN_mod_mul( a, a, a, n, pkcInfo->bnCTX ) );
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

int primeProbable( PKC_INFO *pkcInfo, BIGNUM *n, const int noChecks, 
				   const void *callbackArg )
	{
	BIGNUM *a = &pkcInfo->tmp1, *n_1 = &pkcInfo->tmp2, *u = &pkcInfo->tmp3;
	int i, k, iterationCount = 0, bnStatus = BN_STATUS, status;

	/* Set up various values */
	CK( BN_MONT_CTX_set( &pkcInfo->montCTX1, n, pkcInfo->bnCTX ) );

	/* Evaluate u as n - 1 = 2^k * u.  Obviously the less one bits in the 
	   LSBs of n, the more efficient this test becomes, however with a 
	   randomly-chosen n value we get an exponentially-decreasing chance 
	   of losing any bits after the first one, which will always be zero 
	   since n starts out being odd */
	CKPTR( BN_copy( n_1, n ) );
	CK( BN_sub_word( n_1, 1 ) );
	for( k = 1; !BN_is_bit_set( n_1, k ) && \
				iterationCount++ < FAILSAFE_ITERATIONS_MAX; k++ );
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();
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

int generatePrime( PKC_INFO *pkcInfo, BIGNUM *candidate, const int noBits, 
				   const long exponent, const void *callbackArg )
	{
	MESSAGE_DATA msgData;
	const int noChecks = getNoPrimeChecks( noBits );
	BOOLEAN *sieveArray;
	int offset, oldOffset = 0, startPoint, iterationCount = 0;
	int bnStatus = BN_STATUS, status;

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
		int innerIterationCount = 0;

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
		for( offset = nextEntry( startPoint ); \
			 offset != startPoint && \
				innerIterationCount++ < SIEVE_SIZE + 10; \
			 offset = nextEntry( offset ) )
			{
#ifdef CHECK_PRIMETEST
			LARGE_INTEGER tStart, tStop;
			BOOLEAN passedFermat, passedOldPrimeTest;
			int oldTicks, newTicks, ratio;
#endif /* CHECK_PRIMETEST */
			long remainder;

			/* If this candidate is divisible by anything, continue */
			if( sieveArray[ offset ] != 0 )
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
			   available (currently it provides no improvement at all over 
			   the use of straight Miller-Rabin).  At the moment it's only 
			   used to sanity-check the MR test, but if a faster version is 
			   ever made available, it can be used as a filter to weed out 
			   most pseudoprimes */
			CK( BN_MONT_CTX_set( &pkcInfo->montCTX1, candidate, 
								 pkcInfo->bnCTX ) );
			CK( BN_set_word( &pkcInfo->tmp1, 2 ) );
			CK( BN_mod_exp_mont( &pkcInfo->tmp2, &pkcInfo->tmp1, candidate, 
								 candidate, pkcInfo->bnCTX,
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
		if( innerIterationCount >= SIEVE_SIZE + 10 )
			retIntError();
		}
	while( status == FALSE &&	/* -ve = error, TRUE = success */
		   iterationCount++ < FAILSAFE_ITERATIONS_MAX );
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();

	/* Clean up */
	zeroise( sieveArray, SIEVE_SIZE * sizeof( BOOLEAN ) );
	clFree( "generatePrime", sieveArray );
	return( ( status == TRUE ) ? CRYPT_OK : status );
	}

/****************************************************************************
*																			*
*							Generate a Random Bignum						*
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
	MESSAGE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
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
