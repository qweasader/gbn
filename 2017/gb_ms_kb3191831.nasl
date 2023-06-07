###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server 2007 Service Pack 3 Remote Code Execution Vulnerability (KB3191831)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811813");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-8631");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-13 11:26:00 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-09-13 09:04:38 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft SharePoint Server 2007 Service Pack 3 Remote Code Execution Vulnerability (KB3191831)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3191831.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Microsoft Office
  software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited the vulnerability to use a specially
  crafted file to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2007 Service Pack 3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3191831");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100751");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
if(!path || "Could not find the install location" >< path)
  exit(0);

# nb: SharePoint Server 2007
if(vers =~ "^12\.") {
  check_path = path + "\12.0\Bin";
  check_file = "xlsrv.dll";

  dllVer = fetch_file_version(sysPath:check_path, file_name:check_file);
  if(dllVer) {
    if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6776.4999")) {
      report = report_fixed_ver(file_checked:check_path + "\" + check_file, file_version:dllVer, vulnerable_range:"12.0 - 12.0.6776.4999", install_path:path);
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);
