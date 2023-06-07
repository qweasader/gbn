###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! Information Disclosure and Cross-Site Scripting Vulnerabilities - Jul17
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810999");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-9933", "CVE-2017-9934");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-20 16:45:00 +0000 (Thu, 20 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-07-06 16:30:45 +0530 (Thu, 06 Jul 2017)");
  script_name("Joomla! Information Disclosure and Cross-Site Scripting Vulnerabilities - Jul17");

  script_tag(name:"summary", value:"Joomla is prone to information disclosure and cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper cache invalidation.

  - The missing CSRF token checks and improper input validation.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow
  remote attackers to gain access to potentially sensitive information and
  conduct cross-site scripting attacks.");

  script_tag(name:"affected", value:"Joomla core versions 1.7.3 through 3.7.2");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.7.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.joomla.org/announcements/release-news/5709-joomla-3-7-3-release.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99451");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99450");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!jVer = get_app_version(cpe:CPE, port:jPort)){
  exit(0);
}

if(version_in_range(version:jVer, test_version:"1.7.3", test_version2:"3.7.2"))
{
  report = report_fixed_ver( installed_version:jVer, fixed_version:"3.7.3");
  security_message( data:report, port:jPort);
  exit(0);
}
exit(0);
