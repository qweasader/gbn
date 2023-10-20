# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803376");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-1375", "CVE-2013-1371", "CVE-2013-0650", "CVE-2013-0646");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-18 13:50:50 +0530 (Thu, 18 Apr 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 April 13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52590");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58436");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58438");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58440");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-09.html");
  script_xref(name:"URL", value:"https://www.cert.be/pro/advisories/adobe-flash-player-air-multiple-vulnerabilities-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial-of-service condition.");
  script_tag(name:"affected", value:"Adobe Flash Player 10.3.183.67 and earlier, and 11.x to 11.6.602.179 on
  Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Heap based overflow via unspecified vectors.

  - Integer overflow via unspecified vectors.

  - Use-after-free errors.");
  script_tag(name:"solution", value:"Upgrade to version 10.3.183.68 or 11.6.602.180.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(!vers)
  exit(0);

if(version_is_less(version:vers, test_version:"10.3.183.68") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.6.602.179"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
