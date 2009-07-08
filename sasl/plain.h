// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef PLAIN_H
#define PLAIN_H

#include "mechanism.h"


class Plain
    : public SaslMechanism
{
public:
    Plain( EventHandler * );

    void parseResponse( const EString & );

    static bool parse( EString & authenticateId,
                       EString & authorizeId,
                       EString & pw,
                       const EString & response );
};


#endif
