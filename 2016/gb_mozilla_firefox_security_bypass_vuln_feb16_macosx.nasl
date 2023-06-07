###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Security Bypass Vulnerability - Feb16 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807069");
  script_version("2021-10-11T13:01:25+0000");
  script_cve_id("CVE-2016-1949");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-11 13:01:25 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 03:07:00 +0000 (Tue, 06 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-02-15 12:47:02 +0530 (Mon, 15 Feb 2016)");
  script_name("Mozilla Firefox Security Bypass Vulnerability - Feb16 (Mac OS X)");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to same-origin policy bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper restriction of
  the interaction between Service Workers and plugins.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to bypass the Same Origin Policy via a crafted web site that
  triggers spoofed responses to requests that use NPAPI.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 44.0.2 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 44.0.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-13");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"44.0.2"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"44.0.2");
  security_message(data:report);
  exit(0);
}
