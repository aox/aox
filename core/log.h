#ifndef LOG_H
#define LOG_H

#include "global.h"

class String;


class Log {
public:
    Log();
    ~Log();

    enum Severity {
        Debug,
        Info,
        Error,
        Disaster
    };

    void log( Severity, const String & );
    void log( const String & s ) { log( Info, s ); }

    void commit( Severity = Info );

    static String severity( Severity );

    static bool disastersYet();

private:
    uint id;
};


void log( const String & );


#endif
