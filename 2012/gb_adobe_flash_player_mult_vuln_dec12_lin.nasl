###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Multiple Vulnerabilities - December12 (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803076");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-5676", "CVE-2012-5677", "CVE-2012-5678");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-12-14 15:33:01 +0530 (Fri, 14 Dec 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - December12 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51560/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56892");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56896");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56898");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027854");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2755801");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-27.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or denial of service.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 10.3.183.48, 11.x before 11.2.202.258 on Linux");
  script_tag(name:"insight", value:"Multiple unspecified errors and integer overflow exists that could lead to
  code execution.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 10.3.183.48 or 11.2.202.258 or later.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(playerVer && playerVer =~ ",")
{
  playerVer = ereg_replace(pattern:",", string:playerVer, replace: ".");
}

if(playerVer)
{
  if(version_is_less(version: playerVer, test_version:"10.3.183.48") ||
     version_in_range(version: playerVer, test_version:"11.0", test_version2:"11.2.202.257")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
