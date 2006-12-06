// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SENDMAIL_H
#define SENDMAIL_H

#include "pagecomponent.h"


class Sendmail
    : public PageComponent
{
public:
    Sendmail();
    void execute();

private:
    class SendmailData * d;
};


#endif
