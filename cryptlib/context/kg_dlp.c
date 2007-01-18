/****************************************************************************
*																			*
*				cryptlib DLP Key Generation/Checking Routines				*
*						Copyright Peter Gutmann 1997-2004					*
*																			*
****************************************************************************/

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
	int bnStatus = BN_STATUS, iterationCount = 0;

	/* j = (p - 1) / q */
	CK( BN_sub_word( p, 1 ) );
	CK( BN_div( j, NULL, p, q, pkcInfo->bnCTX ) );
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
		CK( BN_mod_exp( g, gCounter, j, p, pkcInfo->bnCTX ) );
		}
	while( bnStatusOK( bnStatus ) && BN_is_one( g ) && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED );
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	return( getBnStatus( bnStatus ) );
	}

/* Generate prime numbers for DLP-based PKC's using the Lim-Lee algorithm:

	p = 2 * q * ( prime[1] * ... prime[n] ) + 1 */

static int generateDLPublicValues( PKC_INFO *pkcInfo, const int pBits, 
								   int qBits, void *callBackArg )
	{
	const int safeExpSizeBits = getDLPexpSize( pBits );
	const int noChecks = getNoPrimeChecks( pBits );
	BIGNUM llPrimes[ MAX_NO_PRIMES + 8 ], llProducts[ MAX_NO_FACTORS + 8 ];
	BIGNUM *p = &pkcInfo->dlpParam_p, *q = &pkcInfo->dlpParam_q;
	BOOLEAN primeFound = FALSE;
	int indices[ MAX_NO_FACTORS + 8 ];
	int nPrimes, nFactors, factorBits, i, iterationCount = 0;
	int bnStatus = BN_STATUS, status;

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
		int indexMoved, innerIterationCount = 0;

		/* Initialize the indices for the permutation.  We try the first 
		   nFactors factors first, since any new primes are added at the end */
		indices[ nFactors - 1 ] = nPrimes - 1;
		for( i = nFactors - 2; i >= 0; i-- )
			indices[ i ] = indices[ i + 1 ] - 1;
		BN_mul( &llProducts[ nFactors - 1 ], q, &llPrimes[ nPrimes - 1 ], 
				pkcInfo->bnCTX );
		indexMoved = nFactors - 2;

		/* Test all possible new prime permutations until a prime is found or 
		   we run out of permutations */
		do
			{
			/* Assemble a new candidate prime 2 * q * primes + 1 from the 
			   currently indexed random primes */
			for( i = indexMoved; i >= 0; i-- )
				CK( BN_mul( &llProducts[ i ], &llProducts[ i + 1 ],
							&llPrimes[ indices[ i ] ], pkcInfo->bnCTX ) );
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
				{
				if( indices[ i ] > i )
					{
					indices[ i ]--;
					indexMoved = i;
					break;
					}
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
		while( indices[ nFactors - 1 ] > 0 && \
			   innerIterationCount++ < FAILSAFE_ITERATIONS_LARGE );
		if( innerIterationCount >= FAILSAFE_ITERATIONS_LARGE )
			retIntError();

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
	while( !primeFound && iterationCount++ < FAILSAFE_ITERATIONS_LARGE );
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();

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
		CK( BN_mod( x, x, q, pkcInfo->bnCTX ) );

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
						 pkcInfo->bnCTX ) );
	if( bnStatusOK( bnStatus ) )
		CK( BN_mod_exp_mont( &pkcInfo->dlpParam_y, &pkcInfo->dlpParam_g,
							 &pkcInfo->dlpParam_x, &pkcInfo->dlpParam_p, 
							 pkcInfo->bnCTX, &pkcInfo->dlpParam_mont_p ) );
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
	int length, bnStatus = BN_STATUS;

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

	/* Make sure that the key paramters are valid:

		pLen >= MIN_PKCSIZE_BITS, pLen <= MAX_PKCSIZE_BITS

		2 <= g <= p - 2, g a generator of order q if the q parameter is 
			present (i.e. it's a non-PKCS #3 key)

		y < p */
	length = BN_num_bits( p );
	if( length < MIN_PKCSIZE_BITS || length > MAX_PKCSIZE_BITS )
		return( CRYPT_ARGERROR_STR1 );
	if( BN_num_bits( g ) < 2 )
		return( CRYPT_ARGERROR_STR1 );
	CKPTR( BN_copy( tmp, p ) );
	CK( BN_sub_word( tmp, 1 ) );
	if( bnStatusError( bnStatus ) || BN_cmp( g, tmp ) >= 0 )
		return( CRYPT_ARGERROR_STR1 );
	if( !isPKCS3 )
		{
		CK( BN_mod_exp_mont( tmp, g, &pkcInfo->dlpParam_q, p, pkcInfo->bnCTX,
							 &pkcInfo->dlpParam_mont_p ) );
		if( bnStatusError( bnStatus ) || !BN_is_one( tmp ) )
			return( CRYPT_ARGERROR_STR1 );
		}
	if( BN_cmp( &pkcInfo->dlpParam_y, p ) >= 0 )
		return( CRYPT_ARGERROR_STR1 );

	/* Make sure that the private key value is valid */
	if( !( contextInfoPtr->flags & CONTEXT_ISPUBLICKEY ) )
		{
		CK( BN_mod_exp_mont( tmp, g, &pkcInfo->dlpParam_x, p, pkcInfo->bnCTX,
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
	CK( BN_MONT_CTX_set( &pkcInfo->dlpParam_mont_p, p, pkcInfo->bnCTX ) );
	if( bnStatusOK( bnStatus ) && BN_is_zero( &pkcInfo->dlpParam_y ) )
		CK( BN_mod_exp_mont( &pkcInfo->dlpParam_y, g, x, p, pkcInfo->bnCTX, 
							 &pkcInfo->dlpParam_mont_p ) );

	pkcInfo->keySizeBits = BN_num_bits( p );
	return( getBnStatus( bnStatus ) );
	}
