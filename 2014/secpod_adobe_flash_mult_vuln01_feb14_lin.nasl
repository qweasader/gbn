# Copyright (C) 2014 Greenbone Networks GmbH
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
CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903340");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-0498", "CVE-2014-0499", "CVE-2014-0502");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-02-24 18:04:57 +0530 (Mon, 24 Feb 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - 01 Feb14 (Linux)");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to multiple unspecified and a double free error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, disclose potentially
sensitive information and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 11.2.202.341 on Linux");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.2.202.341 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57057");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65702");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65704");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"11.2.202.341"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"11.2.202.341");
  security_message(port:0, data:report);
  exit(0);
}