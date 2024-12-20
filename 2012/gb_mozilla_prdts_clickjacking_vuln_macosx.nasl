# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802894");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2012-1964");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-07-23 18:40:44 +0530 (Mon, 23 Jul 2012)");
  script_name("Mozilla Products Certificate Page Clickjacking Vulnerability - Mac OS X");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49965");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54581");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027256");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027257");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-54.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain sensitive information
  or bypass certain security restrictions.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.10
  Thunderbird version 5.0 through 12.0
  Mozilla Firefox version 4.x through 12.0
  Thunderbird ESR version 10.x before 10.0.6
  Mozilla Firefox ESR version 10.x before 10.0.6 on Mac OS X");
  script_tag(name:"insight", value:"The certificate warning functionality in
  browser/components/certerror/content/aboutCertError.xhtml fails to handle
  attempted clickjacking of the 'about:certerror' page, allowing
  man-in-the-middle attackers to trick users into adding an unintended
  exception via an IFRAME element");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to clickjacking vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 14.0 or ESR version 10.0.6 or later.

  Upgrade to SeaMonkey version to 2.11 or later.

  Upgrade to Thunderbird version to 14.0 or ESR 10.0.6 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"10.0.5")||
     version_in_range(version:ffVer, test_version:"11.0", test_version2:"12.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.10"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/MacOSX/Version");

if(tbVer)
{
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"10.0.5")||
     version_in_range(version:tbVer, test_version:"11.0", test_version2:"12.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
