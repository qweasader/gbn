# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803149");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-6460");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-07 16:34:42 +0530 (Mon, 07 Jan 2013)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Opera Truncated Dialogs Code Execution Vulnerability - Mac OS X");

  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1028/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55301");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unified/1202/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_mandatory_keys("Opera/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute the code and perform
  other unwanted actions.");

  script_tag(name:"affected", value:"Opera version before 11.67 and 12.x before 12.02 on Mac OS X");

  script_tag(name:"insight", value:"An error in handling of truncated dialogs, can be used to cause the user
  to download and run executables unexpectedly or perform other unwanted actions.");

  script_tag(name:"solution", value:"Upgrade to Opera version 11.67 or 12.02");

  script_tag(name:"summary", value:"Opera is prone to a code execution vulnerability.");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.67") ||
   version_in_range(version:operaVer, test_version:"12.0",  test_version2:"12.01")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
