// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PLAIN_H
#define PLAIN_H

#include "mechanism.h"


class Plain
    : public SaslMechanism
{
public:
    Plain( EventHandler * );

    void readResponse( const String & );

    static bool parse( String & authenticateId,
                       String & authorizeId,
                       String & pw,
                       const String & response );
};


#endif
