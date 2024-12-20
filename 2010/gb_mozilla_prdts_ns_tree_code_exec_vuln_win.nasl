# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800751");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0175");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products 'nsTreeSelection' DoS Vulnerability - Windows");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57390");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023780.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-17.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code on the
  system or cause the browser to crash.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.4

  Thunderbird version proior to 3.0.4

  Firefox version before 3.0.19 and 3.5.x before 3.5.9");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'nsTreeSelection' implementation, that
  allows to execute arbitrary code or application crash via unspecified vectors
  that trigger a call to a certain event handler.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird are prone to a denial of
  service (DoS) vulnerability.");

  script_tag(name:"solution", value:"- Update to Firefox version 3.0.19, 3.5.9 or later

  - Update to Seamonkey version 2.0.4 or later

  - Update to Thunderbird version 3.0.4 or later");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"3.0.19") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.8"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_less(version:tbVer, test_version:"3.0.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
