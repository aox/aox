#ifndef LOG_H
#define LOG_H

#include "global.h"
#include "string.h"

class String;


class Log {
public:
    enum Severity { Debug, Info, Error, Disaster };

    Log();
    ~Log();

    void log( Severity, const String & );
    void log( const String & s ) { log( Info, s ); }
    void commit( Severity = Info );

    static String severity( Severity );
    static bool disastersYet();

private:
    String id;
    uint children;
};


void log( const String & );
void log( Log::Severity, const String & );


#endif
