# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901014");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3114");
  script_name("IBM Lotus Notes RSS Reader Widget HTML Injection Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_ibm_lotus_notes_detect_win.nasl");
  script_mandatory_keys("IBM/LotusNotes/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to steal
cookie-based authentication credentials.");
  script_tag(name:"affected", value:"IBM Lotus Notes Version 8.5 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to error in the RSS reader widget, caused when
items are saved from an RSS feed as local HTML documents. This can be exploited
via a crafted feed.");
  script_tag(name:"solution", value:"The Vendor has released a patch to fix the issue. Please see the
  references for more information.");
  script_tag(name:"summary", value:"IBM Lotus Notes is prone to a HTML Injection vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.scip.ch/?vuldb.4021");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36305");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21403834");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506296/100/0/threaded");
  exit(0);
}

include("version_func.inc");

lotusVer = get_kb_item("IBM/LotusNotes/Win/Ver");
if(!lotusVer)
  exit(0);

if(version_in_range(version:lotusVer, test_version:"8.5", test_version2:"8.50.8330")){
  report = report_fixed_ver(installed_version:lotusVer, vulnerable_range:"8.5 - 8.50.8330");
  security_message(port: 0, data: report);
}
