# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause  denial-of-service condition.");
  script_tag(name:"affected", value:"Adobe Flash Player 10.3.183.61 and earlier, and 11.x to 11.6.602.167 on
  Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - A flaw in the ExternalInterface ActionScript feature.

  - Firefox sandbox does not restrict privileges.

  - Buffer overflow in the Flash Player broker service.");
  script_tag(name:"solution", value:"Update to version 10.3.183.67 or 11.6.602.171.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_oid("1.3.6.1.4.1.25623.1.0.803325");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-04 19:11:31 +0530 (Mon, 04 Mar 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_cve_id("CVE-2013-0648", "CVE-2013-0643", "CVE-2013-0504");

  script_name("Adobe Flash Player Multiple Vulnerabilities -01 March13 (Mac OS X)");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58185");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58186");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52374");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-08.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(!vers)
  exit(0);

if(version_is_less_equal(version:vers, test_version:"10.3.183.61") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.6.602.167"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
