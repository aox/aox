// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef EDITVIEW_H
#define EDITVIEW_H

#include "pagecomponent.h"


class EditView
    : public PageComponent
{
public:
    EditView();

    void execute();

private:
    class EditViewData * d;

    class HtmlForm * form() const;
};


#endif
