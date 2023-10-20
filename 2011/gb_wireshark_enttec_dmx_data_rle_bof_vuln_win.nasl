# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801828");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2010-4538");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Wireshark ENTTEC DMX Data RLE Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45634");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0079");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5539");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to create a denial of service
  or execute arbitrary code.");

  script_tag(name:"affected", value:"Wireshark version 1.4.2.");

  script_tag(name:"insight", value:"The flaw is caused by a boundary error in the 'dissect_enttec_dmx_data()'
  function when processing RLE Compressed DMX data of the ENTTEC protocol
  which can be exploited to cause a buffer overflow via a specially crafted packet.");

  script_tag(name:"solution", value:"Upgrade to the latest version of Wireshark 1.4.3.");

  script_tag(name:"summary", value:"Wireshark is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");


  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_is_equal(version:sharkVer, test_version:"1.4.2")){
  report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"Equal to 1.4.2");
  security_message(port: 0, data: report);
}
