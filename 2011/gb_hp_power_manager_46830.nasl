###############################################################################
# OpenVAS Vulnerability Test
#
# HP Power Manager Unspecified Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:hp:power_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103116");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-03-11 13:29:22 +0100 (Fri, 11 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-0280");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Power Manager Unspecified Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46830");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/66035");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("hp_power_manager_detect.nasl");
  script_mandatory_keys("hp_power_manager/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more details.");

  script_tag(name:"summary", value:"The HP Power Manager is prone to an unspecified cross-site scripting
vulnerability because it fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-based authentication credentials and launch
other attacks.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version:version, test_version:"4.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
