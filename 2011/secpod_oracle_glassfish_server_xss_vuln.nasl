# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = 'cpe:/a:oracle:glassfish_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902456");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2260");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17551/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48797");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/518923");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103167/SOS-11-009.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML and
script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Oracle GlassFish Server version 2.1.1");

  script_tag(name:"insight", value:"The flaw is due to error in the handling of log viewer, which fails to
securely output encode logged values. An unauthenticated attacker can trigger the application to log a malicious
string by entering the values into the username field.");

  script_tag(name:"solution", value:"Apply the security updates.");

  script_tag(name:"summary", value:"GlassFish Server is prone to a cross-site scripting (XSS) vulnerability.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version:"2.1.1")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Equal to 2.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
