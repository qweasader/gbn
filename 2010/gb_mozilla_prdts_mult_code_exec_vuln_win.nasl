# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800754");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0178", "CVE-2010-0177");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple vulnerabilities apr-10 (Windows)");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57393");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0748");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023776.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code on the
  system or cause the browser to crash.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.4 and

  Firefox version 3.0.x before 3.0.19, 3.5.x before 3.5.9, 3.6.x before 3.6.2");

  script_tag(name:"insight", value:"The flaws are due to:

  - A dangling pointer flaw in the 'nsPluginArray window.navigator.plugins object'
  when user loads specially crafted HTML which allows to execute arbitrary code
  via unknown vectors.

  - An error in loading a specially crafted applet, that converts a user mouse
  click into a 'drag-and-drop' action which allows to load a privileged
  'chrome:' URL and execute arbitrary scripting code with privileges.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.19, 3.5.9, 3.6.2

  Upgrade to Seamonkey version 2.0.4");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.1") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.8") ||
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.18"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
