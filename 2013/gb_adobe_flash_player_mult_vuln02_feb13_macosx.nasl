# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803408");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-02-14 13:32:22 +0530 (Thu, 14 Feb 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2013-0637", "CVE-2013-0638", "CVE-2013-0639", "CVE-2013-0642",
                "CVE-2013-0644", "CVE-2013-0645", "CVE-2013-0647", "CVE-2013-0649",
                "CVE-2013-1365", "CVE-2013-1366", "CVE-2013-1367", "CVE-2013-1368",
                "CVE-2013-1369", "CVE-2013-1370", "CVE-2013-1372", "CVE-2013-1373",
                "CVE-2013-1374");
  script_name("Adobe Flash Player Multiple Vulnerabilities -02 (Feb 2013) - Mac OS X");
  script_xref(name:"URL", value:"https://lwn.net/Articles/537746");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57912");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57916");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57919");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57920");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57923");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57924");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57925");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57926");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57927");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57929");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57930");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57933");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52166");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-05.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause buffer
  overflow, remote code execution and corrupt system memory.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 10.3.183.61 and 11.x prior to 11.6.602.167
  on Mac OS X.");

  script_tag(name:"insight", value:"Multiple flaws due to:

  - Dereference already freed memory

  - Use-after-free errors

  - Integer overflow and some unspecified error.");

  script_tag(name:"solution", value:"Update to version 11.6.602.167 or later.");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"10.3.183.61") ||
     version_in_range(version:playerVer, test_version:"11.0", test_version2:"11.6.602.166"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
