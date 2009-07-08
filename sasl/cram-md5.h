// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CRAMMD5_H
#define CRAMMD5_H

#include "mechanism.h"


class CramMD5
    : public SaslMechanism
{
public:
    CramMD5( EventHandler * );

    EString challenge();
    void setChallenge( const EString & );
    void parseResponse( const EString & );
    void verify();

private:
    EString challengeSent;
};


#endif
