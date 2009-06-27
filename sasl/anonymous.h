// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ANONYMOUS_H
#define ANONYMOUS_H

#include "mechanism.h"


class Anonymous
    : public SaslMechanism
{
public:
    Anonymous( EventHandler * );

    void parseResponse( const EString & );
    void verify();
};


#endif
