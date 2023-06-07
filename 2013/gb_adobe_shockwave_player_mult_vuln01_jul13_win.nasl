###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Shockwave Player Multiple Vulnerabilities-01 July13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803834");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-3348");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-07-25 17:45:29 +0530 (Thu, 25 Jul 2013)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities-01 July13 (Windows)");
  script_tag(name:"summary", value:"Adobe Shockwave player is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 12.0.3.133 or later.");
  script_tag(name:"insight", value:"Flaw is due to an error when parsing dir files");
  script_tag(name:"affected", value:"Adobe Shockwave Player before 12.0.3.133 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
code on the target system and corrupt system memory.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61040");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(vers) {
  if(version_is_less(version:vers, test_version:"12.0.3.133"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.3.133");
    security_message(port: 0, data: report);
    exit(0);
  }
}
