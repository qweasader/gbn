# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802216");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_cve_id("CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2377");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities - 01 - (Jul 2011) - Windows");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-20.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48369");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48372");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48373");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-21.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-22.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to execute arbitrary code
  or cause a denial of service.");
  script_tag(name:"affected", value:"Thunderbird version before 3.1.11.
  SeaMonkey versions 2.0.14 and prior.
  Mozilla Firefox versions before 3.6.18 and 4.x through 4.0.1");
  script_tag(name:"insight", value:"- An integer overflow error in the 'Array.reduceRight' method allows remote
    attackers to execute arbitrary code via vectors involving a long JavaScript
    Array object.

  - A use-after-free error exists when handling XUL documents.

  - An error when processing images with the 'multipart/x-mixed-replace' MIME
    type can be exploited to corrupt memory.");
  script_tag(name:"summary", value:"Mozilla Firefox, Seamonkey or Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.18, 5.0 or later,
  Upgrade to Seamonkey version 2.2 or later,
  Upgrade to Thunderbird version 3.1.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.6.18") ||
     version_in_range(version:vers, test_version:"4.0", test_version2:"4.0.1") ||
     version_in_range(version:vers, test_version:"4.0.b1", test_version2:"4.0.b12"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  if(version_is_less_equal(version:smVer, test_version:"2.0.14"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.1.11")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
