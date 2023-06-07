###############################################################################
# OpenVAS Vulnerability Test
#
# Netscape Enterprise Server Authentication Buffer Overflow Vulnerability
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

CPE = "cpe:/a:netscape:enterprise_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811545");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-1999-0853");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-07-28 15:05:05 +0530 (Fri, 28 Jul 2017)");
  script_name("Netscape Enterprise Server Authentication Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Netscape Enterprise Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the
  HTTP Basic Authentication procedure for the servers, which has a buffer overflow
  condition when a long username or password (over 508 characters) are provided.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain root privileges under UNIX and SYSTEM privileges under NT.");

  script_tag(name:"affected", value:"Netscape Enterprise Server 3.5.1, 3.6,
  3.6 SP2");

  script_tag(name:"solution", value:"Upgrade to Netscape Enterprise Server
  3.6 SP3 or later.

  Note:Netscape released service pack 3 for Enterprise Server 3.6 that fixes
  the vulnerability in the web server, the Administration Server remains
  vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://cve.circl.lu/cve/CVE-1999-0853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/847");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_netscape_server_detect.nasl");
  script_mandatory_keys("netscape/enterprise_server/detected");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if (!netport = get_app_port(cpe: CPE))
  exit(0);

if(!netVer = get_app_version(cpe:CPE, port:netport))
  exit(0);

if(netVer == "3.5.1" || netVer == "3.6" || netVer == "3.6SP2") {
  report = report_fixed_ver(installed_version:netVer, fixed_version:"3.6.SP3");
  security_message(data:report, port:netport);
  exit(0);
}

exit(99);
