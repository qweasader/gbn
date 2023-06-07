###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Tools Privilege Escalation And Denial Of Service Vulnerabilities (Mac OS X)
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

CPE = "cpe:/a:vmware:tools";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810266");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2016-7079", "CVE-2016-7080");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-01-10 12:53:05 +0530 (Tue, 10 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Tools Privilege Escalation And Denial Of Service Vulnerabilities (Mac OS X)");

  script_tag(name:"summary", value:"VMware Tools is prone to denial of service and privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  the graphic acceleration functions used in VMware Tools for OSX handle
  memory incorrectly.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to gain privileges or cause a denial of service.");

  script_tag(name:"affected", value:"VMware Tools 9.x and 10.x before 10.0.9
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VMware Tool version 10.0.9 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0014.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92938");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_tools_detect_macosx.nasl");
  script_mandatory_keys("VMwareTools/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmtoolVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmtoolVer =~ "^(9|10)")
{
  if(version_is_less(version:vmtoolVer, test_version:"10.0.9"))
  {
    report = report_fixed_ver(installed_version:vmtoolVer, fixed_version:"10.0.9");
    security_message(data:report);
    exit(0);
  }
}
