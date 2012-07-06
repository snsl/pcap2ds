/* ds2xml.cpp
 *
 * Converts DataSeries format to a readable XML file
 *
 * Copyright (C) 2012 University of Connecticut. All rights reserved.
 *
 * borrowed heavily from ds2txt.cpp in DataSeries package
 *
 * (c) Copyright 2004-2005, Hewlett-Packard Development Company, LP
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

#include "DStoXMLModule.hpp"
#include <DataSeries/TypeIndexModule.hpp>

using namespace std;

void print_usage(char *name)
{
	fprintf(stderr,
		"Usage: %s [options] <filename>\n"
		"  filename is the DataSeries file that will be converted to XML\n"	
		"  Options:\n"
		"    --fields=<fields type=\"...\"><field name=\"...\" ///></fields>\n"
		"    --select '*'|'extent-type-match' '*'|'field,field,field'\n",
		name);
}

int main(int argc, char **argv)
{
	TypeIndexModule source("");
	DStoXMLModule toXML(source);
	string select_extent_type, select_fields;

	while (argc > 2) {
		if (strncmp(argv[1],"--fields=",9)==0) {
			toXML.setFields(argv[1] + 9);
		} else if (strcmp(argv[1],"--select")==0) {
			INVARIANT(argc > 4, "--select needs two arguments");
			INVARIANT(select_extent_type.empty(),
				  "multiple --select arguments specified");
			select_extent_type = argv[2];
			INVARIANT(select_extent_type != "",
				  "--select type needs to be non-empty");
			select_fields = argv[3];
			argv += 2;
			argc -= 2;
		} else {
			print_usage(argv[0]);
			return -1;
		}
		
		argv++;
		argc--;
	}
    
	if (argc!=2) {
		print_usage(argv[0]);
		return -1;
	}

	if (select_extent_type != "") {
		DataSeriesSource dssource(argv[1]);
		string match_extent_type;
		ExtentTypeLibrary &lib = dssource.getLibrary();
		const ExtentType::Ptr match_type 
			= lib.getTypeMatchPtr(select_extent_type, false, true);

		match_extent_type = match_type->getName();
		string xmlspec("<fields type=\"");
		xmlspec.append(match_extent_type);
		xmlspec.append("\">");
		if (select_fields == "*") {
			const ExtentType::Ptr t =
					lib.getTypeMatchPtr(match_extent_type);
			SINVARIANT(t != NULL);
			for(unsigned i = 0; i < t->getNFields(); ++i) {
				xmlspec.append((boost::format("<field name=\"%s\"/>") % t->getFieldName(i)).str());
			}
		} else {
			vector<string> fields;
			split(select_fields,",",fields);
			for(unsigned i=0;i<fields.size();++i) {
				xmlspec.append((boost::format("<field name=\"%s\"/>") % fields[i]).str());
			}
		}
		xmlspec.append("</fields>");


		if (select_extent_type != "*") {
			source.setMatch(select_extent_type);
		}
		toXML.setFields(xmlspec.c_str());
	}

	source.addSource(argv[1]);

	toXML.getAndDeleteShared();
    
	return 0;
}

