###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle VirtualBox Security Updates (oct2017-3236626) 01 - Linux
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811981");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-10407", "CVE-2017-3733", "CVE-2017-10428", "CVE-2017-10392",
                "CVE-2017-10408");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-23 19:30:00 +0000 (Tue, 23 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-10-18 12:48:47 +0530 (Wed, 18 Oct 2017)");
  script_name("Oracle VirtualBox Security Updates (oct2017-3236626) 01 - Linux");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in 'core' component.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to compromise availability
  confidentiality and integrity of the system.");

  script_tag(name:"affected", value:"VirtualBox versions Prior to 5.1.30 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox 5.1.30 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101370");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96269");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101362");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101368");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101371");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!virtualVer = get_app_version(cpe:CPE, nofork: TRUE)){
  exit(0);
}

if(version_is_less(version:virtualVer, test_version:"5.1.30"))
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:"5.1.30");
  security_message(data:report);
  exit(0);
}
