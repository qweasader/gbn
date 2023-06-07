###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Player Insecure 'tpfc.dll' Code Execution Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vmware:player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809790");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2012-1666");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-02-01 11:07:47 +0530 (Wed, 01 Feb 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Player Insecure 'tpfc.dll' Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"VMware Player is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to loading of insecure
  'tpfc.dll' library in thinprint.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to execute arbitrary code with the privileges of the user running
  the affected application.");

  script_tag(name:"affected", value:"VMware Player 4.x before 4.0.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Player version
  4.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://cve.circl.lu/cve/CVE-2012-1666");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55421");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Player/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^4\.")
{
  if(version_is_less(version:vmwareVer, test_version:"4.0.4"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"4.0.4");
    security_message(data:report);
    exit(0);
  }
}
