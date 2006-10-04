// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef COMMAND_H
#define COMMAND_H

#include "global.h"
#include "stringlist.h"
#include "permissions.h"
#include "event.h"
#include "imap.h"

class Log;
class MessageSet;


class Command
    : public EventHandler
{
public:
    Command();
    virtual ~Command();

    static Command * create( IMAP *, const String &, const String &,
                             StringList * );

    virtual void parse();
    virtual void read();
    bool ok() const;

    enum State { Unparsed, Blocked, Executing, Finished };
    State state() const;
    void setState( State );

    bool validIn( IMAP::State ) const;

    String tag() const;

    uint group() const;
    void setGroup( uint );

    IMAP *imap() const;

    enum Response { Tagged, Untagged };
    void respond( const String &, Response = Untagged );
    void setRespTextCode( const String & );

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
    String listMailbox();
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

    void shrink( MessageSet * );

    class Mailbox * mailbox( const String & ) const;
    String mailboxName( const String & ) const;

    void requireRight( Mailbox *, Permissions::Right );
    bool permitted();
    bool permissionChecked() const;

private:
    class CommandData *d;

    friend class CommandTest;
};


#endif
