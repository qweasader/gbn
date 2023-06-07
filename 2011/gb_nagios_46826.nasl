###############################################################################
# OpenVAS Vulnerability Test
#
# Nagios 'layer' Parameter Cross-Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:nagios:nagios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103117");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-03-11 13:29:22 +0100 (Fri, 11 Mar 2011)");
  script_cve_id("CVE-2011-1523");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Nagios 'layer' Parameter XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46826");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");

  script_tag(name:"summary", value:"Nagios is prone to a cross-site scripting (XSS) vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"3.2",test_version2:"3.2.4")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"3.2 - 3.2.4");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
