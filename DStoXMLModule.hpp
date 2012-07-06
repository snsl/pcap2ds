// -*-C++-*-
/*
 * Copyright (C) 2012 University of Connecticut. All rights reserved.
 *
 * Based on DStoTextModule.hpp in DataSeries package
 * 
 * (c) Copyright 2003-2005, Hewlett-Packard Development Company, LP
 *
 * See the file named COPYING for license details
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/** @file
    Module that converts a data series to XML
*/

#ifndef __DSTOXMLMODULE_H
#define __DSTOXMLMODULE_H

#include <DataSeries/DataSeriesModule.hpp>

class DSExpr;
class GeneralField;

/** \brief Writes Extents to a file as they go flying past. */
class DStoXMLModule : public DataSeriesModule {
public:
    DStoXMLModule(DataSeriesModule &source, FILE *xml_dest = stdout);
    // measurements indicate that printing to ostreams is slightly
    // slower than stdio on linux/gcc2, and substantially slower (~4x)
    // on gcc3.  Therefore, this version is provided as an option to
    // allow printing to string buffers, but is not the default.
    DStoXMLModule(DataSeriesModule &source, std::ostream &xml_dest);
    virtual ~DStoXMLModule();
    
    virtual Extent::Ptr getSharedExtent(); // will print extent as a side effect.

    void setPrintSpec(const char *xmlText);

    /// After a call to this, the module owns the printSpec and will free it
    /// when done.
    void setFields(const char *xmlText);
    void setWhereExpr(const std::string &extenttype,
		      const std::string &where_expr_str);

    // need to keep around state because relative printing should be
    // done relative to the first row of the first extent, not the
    // first row of each extent.
    struct PerTypeState {
	PerTypeState();
	~PerTypeState();

	ExtentSeries series;
	std::map<std::string, xmlNodePtr> override_print_specs, print_specs;
	std::vector<std::string> field_names;
	std::vector<GeneralField *> fields;
	std::string where_expr_str;
	DSExpr *where_expr;
    };

private:
    static xmlNodePtr parseXML(std::string xml, const std::string &roottype);

    void setPrintSpec(const std::string &extenttype,
		      const std::string &fieldname,
		      xmlNodePtr printSpec);

    void getExtentPrintSpecs(PerTypeState &state);

    // Also initializes state.fields if necessary.
    void getExtentPrintHeaders(PerTypeState &state);

    // Intiailizes state.where_expr if necessary.
    void getExtentParseWhereExpr(PerTypeState &state);
			       
    DataSeriesModule &source;
    std::ostream *stream_xml_dest;
    FILE *xml_dest;

    std::map<std::string, PerTypeState> type_to_state;
};

#endif
