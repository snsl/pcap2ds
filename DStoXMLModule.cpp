// -*-C++-*-
/*
 * Copyright (C) 2012 University of Connecticut. All rights reserved.
 *
 * Based on DStoTextModule.cpp in DataSeries package
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
    implementation
*/

#include "DStoXMLModule.hpp"
#include <DataSeries/DSExpr.hpp>
#include <DataSeries/GeneralField.hpp>

using namespace std;
using boost::format;

static const string str_star("*");

DStoXMLModule::DStoXMLModule(DataSeriesModule &_source,
			     ostream &xml_dest)
    : source(_source), stream_xml_dest(&xml_dest), xml_dest(NULL)
{
}

DStoXMLModule::DStoXMLModule(DataSeriesModule &_source,
			     FILE *_xml_dest)
    : source(_source), stream_xml_dest(NULL), xml_dest(_xml_dest)
{
}

DStoXMLModule::~DStoXMLModule()
{
    // TODO: delete all the general fields in PerTypeState.
}

void
DStoXMLModule::setPrintSpec(const char *xmlText)
{
    xmlNodePtr cur = parseXML(xmlText, "printSpec");
    xmlChar *extenttype = xmlGetProp(cur, (const xmlChar *)"type");
    INVARIANT(extenttype != NULL, "Error: printSpec missing type attribute");
    xmlChar *fieldname = xmlGetProp(cur, (const xmlChar *)"name");
    INVARIANT(fieldname != NULL, 
	      "Error: printSpec missing field name attribute");
    setPrintSpec((char *)extenttype,(char *)fieldname,cur);
}

void
DStoXMLModule::setPrintSpec(const string &extenttype,
			     const string &fieldname,
			     xmlNodePtr printSpec)
{
    type_to_state[extenttype].override_print_specs[fieldname] = printSpec;
}


void
DStoXMLModule::setFields(const char *xmlText)
{
    xmlNodePtr cur = parseXML(xmlText,"fields");
    xmlChar *extenttype = xmlGetProp(cur, (const xmlChar *)"type");
    INVARIANT(extenttype != NULL, "error fields must have a type!");
    string s_et = reinterpret_cast<char *>(extenttype);
    vector<string> &fields = type_to_state[s_et].field_names;
    for(cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
	if (xmlIsBlankNode(cur)) {
	    cur = cur->next;
	    continue;
	}
	INVARIANT(xmlStrcmp(cur->name, (const xmlChar *)"field") == 0,
	    format("Error: fields sub-element should be field, not '%s")
		  % reinterpret_cast<const char *>(cur->name));
	xmlChar *name = xmlGetProp(cur,(const xmlChar *)"name");
	INVARIANT(name != NULL, "error field must have a name");
	string s_name = (char *)name;
	fields.push_back(s_name);
    }
}

void
DStoXMLModule::setWhereExpr(const string &extenttype,
			     const string &where_expr_str)
{
    INVARIANT(type_to_state[extenttype].where_expr_str.empty(),
	      format("Error: multiple where expr for extent type '%s'")
	      % extenttype);
    INVARIANT(!where_expr_str.empty(),
	      format("Error: empty where expression for extent type '%s'")
	      % extenttype);
    type_to_state[extenttype].where_expr_str = where_expr_str;
}


void
DStoXMLModule::getExtentPrintSpecs(PerTypeState &state)
{
    if (!state.print_specs.empty()) {
	return;
    }
    state.print_specs = state.override_print_specs;
    ExtentType::Ptr type = state.series.getTypePtr();
    const xmlDocPtr doc = type->getXmlDescriptionDoc();
    xmlNodePtr cur = xmlDocGetRootElement(doc);
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
	while(cur != NULL && xmlIsBlankNode(cur)) {
	    cur = cur->next;
	}
	if (cur == NULL)
	    break;
	xmlChar *fname = xmlGetProp(cur,(const xmlChar *)"name");
	SINVARIANT(fname != NULL);
	string s_fname = reinterpret_cast<char *>(fname);
	if (state.print_specs[s_fname] == NULL) {
	    state.print_specs[s_fname] = cur;
	}
	cur = cur->next;
    }
}

void
DStoXMLModule::getExtentParseWhereExpr(PerTypeState &state)
{
    if ((state.where_expr == NULL) &&
	(!state.where_expr_str.empty())) {
	state.where_expr = DSExpr::make(state.series, state.where_expr_str);
    }

}


DStoXMLModule::PerTypeState::PerTypeState()
    : where_expr(NULL)
{}

DStoXMLModule::PerTypeState::~PerTypeState()
{
    for(vector<GeneralField *>::iterator i = fields.begin();
	i != fields.end(); ++i) {
	delete *i;
	*i = NULL;
    }
    fields.clear();
    for(map<string, xmlNodePtr>::iterator i = override_print_specs.begin();
	i != override_print_specs.end(); ++i) {
	xmlFreeDoc(i->second->doc);
	i->second = NULL;
    }
    override_print_specs.clear();
    delete where_expr;
    where_expr = NULL;
}

void
DStoXMLModule::getExtentPrintHeaders(PerTypeState &state) 
{
    if (state.field_names.empty()) {
	for(unsigned i=0;i<state.series.getTypePtr()->getNFields();++i) {
	    state.field_names.push_back(state.series.getTypePtr()->getFieldName(i));
	}
    }
    if (state.fields.empty()) {
	for(vector<string>::iterator i = state.field_names.begin();
	    i != state.field_names.end(); ++i) {
	    xmlNodePtr field_desc = state.print_specs[*i];
	    state.fields.push_back(GeneralField::create(field_desc,
							state.series,*i));
	}
    }
}

Extent::Ptr DStoXMLModule::getSharedExtent() {
    Extent::Ptr e = source.getSharedExtent();
    if (e == NULL) {
	return e;
    }
    if (e->type->getName() == "DataSeries: XmlType") {
	return e;
    }

    if (e->type->getName() == "DataSeries: ExtentIndex") {
	return e;
    }

    PerTypeState &state = type_to_state[e->type->getName()];

    state.series.setExtent(e);
    getExtentParseWhereExpr(state);
    getExtentPrintSpecs(state);
    getExtentPrintHeaders(state);

    for (;state.series.morerecords();++state.series) {
	if (!state.where_expr || state.where_expr->valBool()) {

	    const string &name = state.series.getTypePtr()->getName();
	    if (xml_dest == NULL) {
		*stream_xml_dest << "<fields type=\"" << name << "\">\n";
	    } else {
		fprintf(xml_dest, "<fields type=\"%s\">\n", name.c_str());
	    }

	    // the state.fields[i] GeneralField has a typed_field
	    // member that we should be able to get the field name
	    // from, but since its protected, we can't.  So,
	    // instead, we will just iterate through the fields_names 
	    // vector while we iterate through the fields vector
	    vector<string>::iterator i2 = state.field_names.begin();
	    for(unsigned int i=0;i<state.fields.size();i++,i2++) {
		if (xml_dest == NULL) {
		    *stream_xml_dest << "  <field name=\"" << *i2 <<
						  "\" value=\"";
		    state.fields[i]->write(*stream_xml_dest);
		    *stream_xml_dest << "\">\n";
		} else {
		    fprintf(xml_dest, "  <field name=\"%s\" value=\"",
			    i2->c_str());
		    state.fields[i]->write(xml_dest);
		    fputs("\">\n", xml_dest);
		}
	    }
	    if (xml_dest == NULL) {
		*stream_xml_dest << "</fields>\n";
	    } else {
		fputs("</fields>\n", xml_dest);
	    }
	}
    }
    return e;
}

// this interface assumes you're just going to leak the document
xmlNodePtr
DStoXMLModule::parseXML(string xml, const string &roottype)
{
    LIBXML_TEST_VERSION;
    xmlKeepBlanksDefault(0);
    xmlDocPtr doc = xmlParseMemory((char *)xml.data(),xml.size());
    INVARIANT(doc != NULL,
	      format("Error: parsing %s failed") % roottype);
    xmlNodePtr cur = xmlDocGetRootElement(doc);
    INVARIANT(cur != NULL,
	      format("Error: %s missing document") % roottype.c_str());
    INVARIANT(xmlStrcmp(cur->name, (const xmlChar *)roottype.c_str()) == 0,
	      format("Error: %s has wrong type") % roottype);
    return cur;
}
    
