###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Tools Shared Folders Out-of-bounds read Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vmware:tools";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813700");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2018-6969");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-11 14:47:00 +0000 (Tue, 11 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-07-23 16:50:47 +0530 (Mon, 23 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Tools Shared Folders Out-of-bounds read Vulnerability (Windows)");

  script_tag(name:"summary", value:"VMware Tools is prone to an out of bounds read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds read
  vulnerability in the Shared Folders feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to obtain sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"VMware Tools 10.x and prior on Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Tool version 10.3.0 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2018-0017.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104737");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_tools_detect_win.nasl");
  script_mandatory_keys("VMwareTools/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vmtoolVer = infos['version'];
vmPath = infos['location'];

if(version_is_less(version:vmtoolVer, test_version:"10.3.0"))
{
  report = report_fixed_ver(installed_version:vmtoolVer, fixed_version:"10.3.0", install_path:vmPath);
  security_message(data:report);
  exit(0);
}
