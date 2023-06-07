###############################################################################
# OpenVAS Vulnerability Test
#
# 7-Zip Unspecified Archive Handling Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800256");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6536");
  script_name("7-Zip Unspecified Archive Handling Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29434");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28285");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/0914/references");
  script_xref(name:"URL", value:"http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_7zip_detect_lin.nasl");
  script_mandatory_keys("7zip/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code in the
  affected system and cause denial of service.");
  script_tag(name:"affected", value:"7zip version prior to 4.57 on Linux");
  script_tag(name:"insight", value:"This flaw occurs due to memory corruption while handling malformed archives.");
  script_tag(name:"solution", value:"Upgrade to 7zip version 4.57.");
  script_tag(name:"summary", value:"7zip is prone to an unspecified vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

zipVer = get_kb_item("7zip/Lin/Ver");
if(!zipVer)
  exit(0);

if(version_is_less(version:zipVer, test_version:"4.57")){
  report = report_fixed_ver(installed_version:zipVer, fixed_version:"4.57");
  security_message(port: 0, data: report);
}
