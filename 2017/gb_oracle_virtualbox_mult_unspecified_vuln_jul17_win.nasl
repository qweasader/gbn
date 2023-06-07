###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Virtualbox Multiple Unspecified Vulnerabilities July17 (Windows)
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811529");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-10204", "CVE-2017-10129", "CVE-2017-10210", "CVE-2017-10233",
                "CVE-2017-10236", "CVE-2017-10237", "CVE-2017-10238", "CVE-2017-10239",
                "CVE-2017-10240", "CVE-2017-10241", "CVE-2017-10242", "CVE-2017-10235",
                "CVE-2017-10209", "CVE-2017-10187");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-19 11:38:31 +0530 (Wed, 19 Jul 2017)");
  script_name("Oracle Virtualbox Multiple Unspecified Vulnerabilities July17 (Windows)");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified errors related to core component of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on availability, confidentiality and integrity.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.1.24
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox 5.1.24 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99631");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99640");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99642");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99645");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99667");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99668");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99683");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99705");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99709");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99711");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:virtualVer, test_version:"5.1.24"))
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:"5.1.24");
  security_message(data:report);
  exit(0);
}