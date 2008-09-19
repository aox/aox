// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef COMMAND_H
#define COMMAND_H

#include "imapresponse.h"
#include "permissions.h"
#include "stringlist.h"
#include "event.h"
#include "imap.h"

class Log;
class ImapParser;
class MessageSet;


class Command
    : public EventHandler
{
public:
    Command();
    Command( IMAP * );
    virtual ~Command();

    static Command * create( IMAP *, const String &, const String &,
                             ImapParser * );

    virtual void parse();
    virtual void read();
    bool ok() const;

    void setParser( ImapParser * );
    ImapParser * parser() const;

    enum State { Unparsed, Blocked, Executing, Finished, Retired };
    State state() const;
    void setState( State );

    void setAllowedState( IMAP::State ) const;

    String tag() const;
    String name() const;

    bool usesMsn() const;

    uint group() const;
    void setGroup( uint );

    IMAP * imap() const;

    void respond( const String & );
    void setRespTextCode( const String & );

    enum Error { No, Bad };
    void error( Error, const String & );

    void waitFor( ImapResponse * );
    void finish();
    void emitResponses();
    void checkUntaggedResponses();

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
    UString listMailbox();
    MessageSet set( bool );
    uint msn();
    String flag();
    class Mailbox * mailbox();
    UString mailboxName();

    void end();
    const String following() const;

    enum QuoteMode {
        AString, NString, PlainString
    };
    static String imapQuoted( const String &,
                              const QuoteMode = PlainString );
    String imapQuoted( Mailbox *, Mailbox * = 0 );

    void shrink( MessageSet * );


    void requireRight( Mailbox *, Permissions::Right );
    bool permitted();

    ImapSession * session();

private:
    class CommandData *d;

    friend class CommandTest;
};


#endif
