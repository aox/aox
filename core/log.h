// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOG_H
#define LOG_H

#include "global.h"
#include "string.h"

class String;


class Log
    : public Garbage
{
public:
    enum Severity { Debug, Info, Significant, Error, Disaster };

    Log();
    Log( Log * );
    void log( const String &, Severity = Info );
    String id();

    Log * parent() const;
    bool isChildOf( Log * ) const;

    static const char * severity( Severity );
    static bool disastersYet();

private:
    String ide;
    uint children;
    Log * p;
};


void log( const String &, Log::Severity = Log::Info );


#endif
