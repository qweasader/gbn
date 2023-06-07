# OpenVAS Vulnerability Test
# Description: Sympa invalid LDAP password DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:sympa:sympa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14299");
  script_version("2020-02-25T07:14:55+0000");
  script_tag(name:"last_modification", value:"2020-02-25 07:14:55 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_xref(name:"OSVDB", value:"8689");

  script_name("Sympa < 3.4.4.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("sympa_detect.nasl");
  script_mandatory_keys("sympa/detected");

  script_tag(name:"solution", value:"Update to version 3.4.4.1 or newer.");

  script_tag(name:"summary", value:"Sympa contains a flaw in the processing of LDAP passwords.");

  script_tag(name:"impact", value:"An attacker, exploiting this flaw, would need network
  access to the webserver. A successful attack would crash the sympa application and render it useless.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.4.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
