// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FETCH_H
#define FETCH_H

#include "command.h"


class Message;
class BodyPart;
class Multipart;


class Fetch
    : public Command
{
public:
    Fetch( bool = false );

    enum State { Initial, Responding };

    void parse();
    void execute();

    void parseAttribute( bool alsoMacro );
    void parseBody();

    String dotLetters( uint, uint );

private:
    String fetchResponse( Message *, uint, uint );
    String flagList( Message *, uint );
    String internalDate( Message * );
    String envelope( Message * );
    String bodyStructure( Multipart *, bool );
    String singlePartStructure( BodyPart *, bool );
    void removeInvalidUids();
    void sendFetchQueries();

private:
    bool uid;
    class FetchData * d;
};


#endif
