###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Multiple Information Disclosure Vulnerabilities - (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802545");
  script_version("2022-02-17T14:14:34+0000");
  script_cve_id("CVE-2010-5074", "CVE-2002-2437", "CVE-2002-2436");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-12-09 14:17:09 +0530 (Fri, 09 Dec 2011)");
  script_name("Mozilla Products Multiple Information Disclosure Vulnerabilities - (Windows)");

  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2010-5074");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2002-2436");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2002-2437");
  script_xref(name:"URL", value:"http://vrda.jpcert.or.jp/feed/en/NISTNVD_CVE-2010-5074_AD_1.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to obtain sensitive information
  about visited web pages.");
  script_tag(name:"affected", value:"SeaMonkey version prior to 2.1,
  Thunderbird version prior to 3.3 and
  Mozilla Firefox version prior to 4.0 on Windows");
  script_tag(name:"insight", value:"The flaws are due to

  - An error in layout engine, executes different code for visited and
    unvisited links during the processing of CSS token sequences.

  - An error in JavaScript implementation, which does not properly restrict
    the set of values of objects returned by the getComputedStyle method.

  - An error in Cascading Style Sheets (CSS) implementation, which fails to
    handle the visited pseudo-class.");
  script_tag(name:"summary", value:"Mozilla firefox/seamonkey/thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 4.0 or later, Upgrade to SeaMonkey version to 2.1 or later,
  Upgrade to Thunderbird version 3.3 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"4.0"))
  {
     report = report_fixed_ver(installed_version:vers, fixed_version:"4.0");
     security_message(port: 0, data: report);
     exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.1"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.3")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.3");
    security_message(port: 0, data: report);
  }
}
