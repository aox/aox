// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SASLLOGIN_H
#define SASLLOGIN_H

#include "mechanism.h"


class SaslLogin
    : public SaslMechanism
{
public:
    SaslLogin( EventHandler * );
    EString challenge();
    void parseResponse( const EString & );
};


#endif
