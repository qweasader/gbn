###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple DoS Vulnerabilities Jul17 (MAC OS X)
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811427");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-11408", "CVE-2017-11407", "CVE-2017-11406", "CVE-2017-11410",
                "CVE-2017-11411");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-20 18:05:24 +0530 (Thu, 20 Jul 2017)");
  script_name("Wireshark Multiple DoS Vulnerabilities Jul17 (MAC OS X)");

  script_tag(name:"summary", value:"wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  an error in 'DOCSIS', 'MQ', 'AMQP', 'openSAFETY', 'WBXML' dissectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to crash the affected application, resulting in denial-of-service
  conditions.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 to 2.2.7, and 2.0.0
  to 2.0.13 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.2.8 or
  2.0.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-34.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99894");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-35.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-36.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-13.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-28.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(wirversion =~ "(^2\.0)")
{
  if(version_is_less(version:wirversion, test_version:"2.0.14")){
    fix = "2.0.14";
  }
}

else if(wirversion =~ "(^2\.2)")
{
  if(version_is_less(version:wirversion, test_version:"2.2.8")){
    fix = "2.2.8";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix);
  security_message(data:report);
  exit(0);
}