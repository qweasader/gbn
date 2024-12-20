# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801497");
  script_version("2024-02-12T14:37:47+0000");
  script_tag(name:"last_modification", value:"2024-02-12 14:37:47 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-3769", "CVE-2010-3768", "CVE-2010-3776");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities (MFSA2010-74, MFSA2010-75, MFSA2010-78) - Windows");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=660420");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=527276");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-74.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-75.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-78.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service and
  execute arbitrary code.");

  script_tag(name:"affected", value:"Seamonkey version before 2.0.11

  Firefox version before 3.5.16 and 3.6.x before 3.6.13

  Thunderbird version before 3.0.11 and 3.1.x before 3.1.7");

  script_tag(name:"insight", value:"The flaws are due to:

  - Multiple unspecified vulnerabilities in the browser engine, which allows
  attackers to cause a denial of service.

  - 'Line-breaking' implementation which does not properly handle long strings
  which allow remote attackers to execute arbitrary code via a crafted 'document.write' call.

  - Not properly validate downloadable fonts before use within an operating
  system's font implementation.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird are prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.16 or 3.6.13 or later

  Upgrade to Seamonkey version 2.0.11 or later

  Upgrade to Thunderbird version 3.0.11 or 3.1.7 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.13") ||
     version_is_less(version:ffVer, test_version:"3.5.16"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.11"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_in_range(version:tbVer, test_version:"3.1", test_version2:"3.1.7") ||
     version_is_less(version:tbVer, test_version:"3.0.11")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
