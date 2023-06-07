###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Multiple Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802150");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2981", "CVE-2011-2984", "CVE-2011-2378");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45666/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49214");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49219");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-30.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl",
                      "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will likely
  result in denial-of-service conditions.");
  script_tag(name:"affected", value:"SeaMonkey version 2.0 through 2.2
  Mozilla Firefox version before 3.6.20
  Thunderbird version 3.0 through 3.1.11");
  script_tag(name:"insight", value:"The flaws are due to

  - An error in the 'event-management' implementation, which fails to select
    the context for script to run in.

  - Improper handling of the dropping of a tab element.

  - An error in 'appendChild()' function, which fails to handle DOM objects.");
  script_tag(name:"summary", value:"Mozilla firefox/seamonkey/thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.20 or later, Upgrade to SeaMonkey version to 2.3 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.6.20")){
     report = report_fixed_ver(installed_version:vers, fixed_version:"3.6.20");
     security_message(port: 0, data: report);
     exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"2.0", test_version2:"2.2"))
  {
     report = report_fixed_ver(installed_version:vers, vulnerable_range:"2.0 - 2.2");
     security_message(port: 0, data: report);
     exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"3.0", test_version2:"3.1.11")){
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"3.0 - 3.1.11");
    security_message(port: 0, data: report);
  }
}
