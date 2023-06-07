# OpenVAS Vulnerability Test
# Description: F-Secure Policy Manager Server fsmsh.dll module DoS
#
# Authors:
# David Maciejak <david dot maciejak at gmail dot com>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
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

CPE = "cpe:/a:f-secure:policy_manager_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80061");
  script_version("2022-09-07T10:10:59+0000");
  script_tag(name:"last_modification", value:"2022-09-07 10:10:59 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_cve_id("CVE-2007-2964");
  script_xref(name:"OSVDB", value:"36723");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("F-Secure Policy Manager Server < 7.0.1 'fsmsh.dll module' DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_fsecure_policy_manager_http_detect.nasl");
  script_mandatory_keys("fsecure/policy_manager/server/detected");

  script_xref(name:"URL", value:"http://www.f-secure.com/security/fsc-2007-4.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/24233");

  script_tag(name:"summary", value:"F-Secure Policy Manager Server is prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A malicious user can forge a request to query a MS-DOS device name through the
  'fsmsh.dll' CGI module, which will prevent legitimate users from accessing the service using the Manager Console.");

  script_tag(name:"solution", value:"Update to version 7.01 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"7.01")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"7.01");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
