###############################################################################
# OpenVAS Vulnerability Test
#
# RealNetworks RealPlayer Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# - Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-02-25
#     Added CVE-2011-0694 and updated the vulnerability insight.
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.801749");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-02-18 17:42:11 +0100 (Fri, 18 Feb 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4393", "CVE-2011-0694");
  script_name("RealNetworks RealPlayer Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43098");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46047");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64960");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0240");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/01272011_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to compromise a
  vulnerable system by convincing a user to open a malicious media file or
  visit a specially crafted web page.");

  script_tag(name:"affected", value:"RealPlayer versions 11.0 through 11.1

  RealPlayer SP versions 1.0 through 1.1.5 (12.x)

  RealPlayer versions 14.0.0 through 14.0.1.");

  script_tag(name:"insight", value:"The flaws are caused due,

  - a buffer overflow error in the 'vidplin.dll' module when processing
  malformed header data.

  - temporary files that store references to media files having predictable
  names. This can be exploited in combination with the
  'OpenURLInPlayerBrowser()' method of a browser plugin to execute the file.");

  script_tag(name:"solution", value:"Upgrade to RealPlayer version 14.0.2 or later.");

  script_tag(name:"summary", value:"RealPlayer is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(!rpVer || rpVer !~ "^1[12]\.") {
  exit(0);
}

if(version_in_range(version:rpVer, test_version:"11.0.0", test_version2:"11.0.2.2315") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.879") ||
   version_in_range(version:rpVer, test_version:"12.0.1", test_version2:"12.0.1.632")) {
  report = report_fixed_ver(installed_version:rpVer, fixed_version:"14.0.2");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);