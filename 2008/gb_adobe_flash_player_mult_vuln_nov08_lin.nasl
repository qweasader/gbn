###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Multiple Vulnerabilities - Nov08 (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800055");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-11-12 16:32:06 +0100 (Wed, 12 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4818", "CVE-2008-4819", "CVE-2008-4820", "CVE-2008-4821",
                "CVE-2008-4822", "CVE-2008-4823", "CVE-2008-4824", "CVE-2008-5361",
                "CVE-2008-5362", "CVE-2008-5363");
  script_name("Adobe Flash Player Multiple Vulnerabilities - Nov08 (Linux)");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb08-20.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32129");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb08-22.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful attack could allow malicious people to bypass certain
  security restrictions or manipulate certain data.");
  script_tag(name:"affected", value:"Adobe Flash Player 9.0.124.0 and earlier on Linux.");
  script_tag(name:"insight", value:"Multiple flaws are reported in Adobe Flash Player, see the references
  for more information.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player 9.0.151.0 or 10.0.12.36.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple security bypass vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

adobeVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!adobeVer){
  exit(0);
}

if(version_is_less_equal(version:adobeVer, test_version:"9.0.124.0")){
  report = report_fixed_ver(installed_version:adobeVer, vulnerable_range:"Less than or equal to 9.0.124.0");
  security_message(port: 0, data: report);
}