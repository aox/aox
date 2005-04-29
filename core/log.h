// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOG_H
#define LOG_H

#include "global.h"
#include "string.h"

class String;


class Log {
public:
    enum Facility {
        General,
        Configuration, Database, Authentication, IMAP, SMTP, Server
    };
    enum Severity { Debug, Info, Error, Disaster };

    Log( Facility );
    void setFacility( Facility );
    void log( const String &, Severity = Info );
    void commit( Severity = Info );
    ~Log();

    static const char * severity( Severity );
    static const char * facility( Facility );
    static bool disastersYet();

private:
    String id;
    Facility fc;
    uint children;
};


void log( const String &, Log::Severity = Log::Info );
void commit( Log::Severity = Log::Info );


#endif
