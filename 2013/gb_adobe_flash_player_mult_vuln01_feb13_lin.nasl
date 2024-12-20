# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803406");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-02-12 13:17:51 +0530 (Tue, 12 Feb 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2013-0633", "CVE-2013-0634");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 (Feb 2013) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52116");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57787");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57788");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81866");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-04.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause buffer overflow,
  remote code execution, and corrupt system memory.");
  script_tag(name:"affected", value:"Adobe Flash Player prior to 10.3.183.51 and 11.x prior to 11.2.202.262
  on Linux");
  script_tag(name:"insight", value:"Error while processing multiple references to an unspecified object which can
  be exploited by tricking the user to accessing a malicious crafted SWF file.");
  script_tag(name:"solution", value:"Update to version 11.2.202.262 or later.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(vers) {
  if(version_is_less(version:vers, test_version:"10.3.183.51") ||
     version_in_range(version:vers, test_version:"11.0", test_version2:"11.2.202.261"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
