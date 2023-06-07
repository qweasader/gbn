###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Connect 'registration module' Cross-Site Scripting Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809471");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-7851");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-11-15 13:01:25 +0530 (Tue, 15 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect 'registration module' Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Adobe Connect is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as adobe connect does
  not adequately validate user inputs in the events registration module.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause cross-site scripting attack.");

  script_tag(name:"affected", value:"Adobe Connect versions before 9.5.7 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Connect version 9.5.7 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb16-35.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94152");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("adobe/connect/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!acPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!acVer = get_app_version(cpe:CPE, port:acPort)){
  exit(0);
}

if(version_is_less(version:acVer, test_version:"9.5.7"))
{
  report = report_fixed_ver(installed_version:acVer, fixed_version:"9.5.7");
  security_message(data:report, port:acPort);
  exit(0);
}

