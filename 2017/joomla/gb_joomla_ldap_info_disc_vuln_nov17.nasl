###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! Core LDAP Information Disclosure Vulnerability Nov17
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
  script_oid("1.3.6.1.4.1.25623.1.0.811896");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-14596");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-27 17:43:00 +0000 (Wed, 27 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-11-08 10:36:51 +0530 (Wed, 08 Nov 2017)");
  script_name("Joomla! Core LDAP Information Disclosure Vulnerability Nov17");

  script_tag(name:"summary", value:"Joomla is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an inadequate
  escaping in the LDAP authentication plugin.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to disclose username and password.");

  script_tag(name:"affected", value:"Joomla core version 1.5.0 through 3.8.1");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.8.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/714-20171101-core-ldap-information-disclosure.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100898");
  script_xref(name:"URL", value:"https://blog.ripstech.com/2017/joomla-takeover-in-20-seconds-with-ldap-injection-cve-2017-14596");

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

if(version_in_range(version:jVer, test_version:"1.5.0", test_version2:"3.8.1"))
{
  report = report_fixed_ver( installed_version:jVer, fixed_version:"3.8.2");
  security_message( data:report, port:jPort);
  exit(0);
}
exit(0);