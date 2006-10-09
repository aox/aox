// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpparser.h"


/*! \class SmtpParser smtpparser.h
    SMTP-specific ABNF parsing functions.

    This subclass of AbnfParser provides functions to parse SMTP
    protocol elements as defined in RFC 2821.
*/

/*! Creates a new SmtpParser object for the string \a s, which is
    assumed to be a complete SMTP command line (not including the
    terminating CRLF), as received from the client.
*/

SmtpParser::SmtpParser( const String &s )
    : AbnfParser( s )
{
}
