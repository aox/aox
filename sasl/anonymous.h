// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ANONYMOUS_H
#define ANONYMOUS_H

#include "mechanism.h"


class Anonymous
    : public SaslMechanism
{
public:
    Anonymous( EventHandler * );

    void readResponse( const String & );
    void verify();
};


#endif
