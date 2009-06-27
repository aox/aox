// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
