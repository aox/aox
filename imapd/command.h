#ifndef COMMAND_H
#define COMMAND_H

#include "global.h"
#include "stringlist.h"
#include "event.h"

class IMAP;
class Arena;
class Log;
class MessageSet;


class Command
    : public EventHandler
{
public:
    Command();
    virtual ~Command();

    static Command * create( IMAP *, const String &, const String &,
                             StringList *, Arena * );

    virtual void parse();
    virtual void read();
    bool ok() const;

    enum State { Blocked, Executing, Finished };
    State state() const;
    void setState( State );

    uint group() const;
    void setGroup( uint );

    Log * logger() const;
    IMAP * imap() const;

    enum Response { Tagged, Untagged };
    void respond( const String &, Response = Untagged );

    enum Error { No, Bad };
    void error( Error, const String & );

    void finish();
    void emitResponses();

    char nextChar();
    void step( uint = 1 );
    bool present( const String & );
    void require( const String & );
    String digits( uint, uint );
    String letters( uint, uint );
    void nil();
    void space();
    uint number();
    uint nzNumber();
    String atom();
    String listChars();
    String quoted();
    String literal();
    String string();
    String nstring();
    String astring();
    MessageSet set( bool );
    uint msn();
    String flag();
    void end();
    const String following() const;

    enum QuoteMode {
        AString, NString, PlainString
    };
    static String imapQuoted( const String &,
                              const QuoteMode = PlainString );

private:
    class CommandData *d;

    friend class CommandTest;
};


#endif
