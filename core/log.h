// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOG_H
#define LOG_H

#include "global.h"
#include "string.h"

class String;


class Log {
public:
    enum Severity { Debug, Info, Error, Disaster };
    enum Facility {
        Immediate, Configuration, Database, Authentication, IMAP, SMTP
    };

    Log( Facility );
    ~Log();

    void log( Severity, const String & );
    void log( const String & s ) { log( Info, s ); }
    void commit( Severity = Info );

    static String severity( Severity );
    static String facility( Facility );
    static bool disastersYet();

private:
    String id;
    Facility fc;
    uint children;
};


#endif
