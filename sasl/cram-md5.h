#ifndef CRAMMD5_H
#define CRAMMD5_H

#include "mechanism.h"


class CramMD5
    : public SaslMechanism
{
public:
    CramMD5( EventHandler * );

    String challenge();
    void setChallenge( const String & );
    void readResponse( const String & );
    void verify();

private:
    String challengeSent;
};


#endif
