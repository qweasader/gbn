# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902775");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"creation_date", value:"2011-12-22 12:14:45 +0530 (Thu, 22 Dec 2011)");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_name("Mozilla Products Multiple Vulnerabilities - Dec 11 (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47302/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51133");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51134");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51136");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-53.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-54.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-56.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-58.html");

  script_tag(name:"qod_type", value:"registry");
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
  script_tag(name:"affected", value:"SeaMonkey version before 2.6
  Thunderbird version 5.0 through 8.0
  Mozilla Firefox version Firefox 4.x through 8.0");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Unspecified errors in browser engine.

  - An error exists within the YARR regular expression library when parsing
    javascript content.

  - Not properly handling SVG animation accessKey events when JavaScript is
    disabled. This can lead to the user's key strokes being leaked.

  - An error exists within the handling of OGG <video> elements.");
  script_tag(name:"summary", value:"Mozilla firefox/thunderbird/seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 9.0 or later, Upgrade to SeaMonkey version to 2.6 or later,
  Upgrade to Thunderbird version to 9.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"4.0", test_version2:"8.0"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.0 - 8.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.6"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.6");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"5.0", test_version2:"8.0")){
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"5.0 - 8.0");
    security_message(port: 0, data: report);
  }
}
