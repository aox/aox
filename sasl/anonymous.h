#ifndef ANONYMOUS_H
#define ANONYMOUS_H

#include "mechanism.h"


class Anonymous
    : public SaslMechanism
{
public:
    Anonymous( Command * );

    void readResponse( const String & );
};


#endif
