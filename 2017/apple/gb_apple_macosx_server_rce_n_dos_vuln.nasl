###############################################################################
# OpenVAS Vulnerability Test
#
# Apple OS X Server Denial of Service And RCE Vulnerabilities (HT208102)
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

CPE = "cpe:/o:apple:os_x_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811791");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-10978", "CVE-2017-10979");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-09-26 13:29:15 +0530 (Tue, 26 Sep 2017)");
  script_name("Apple OS X Server Denial of Service And RCE Vulnerabilities (HT208102)");

  script_tag(name:"summary", value:"Apple OS X Server is prone to denial of service and remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  out-of-bound issues in FreeRADIUS.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service condition and execute arbitrary code on affected
  system.");

  script_tag(name:"affected", value:"Apple OS X Server before 5.4");

  script_tag(name:"solution", value:"Upgrade to Apple OS X Server 5.4 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99893");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_macosx_server_detect.nasl");
  script_mandatory_keys("Apple/OSX/Server/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!serVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:serVer, test_version:"5.4"))
{
  report = report_fixed_ver(installed_version:serVer, fixed_version:"5.4");
  security_message(data:report);
  exit(0);
}
exit(0);
