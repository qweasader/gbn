# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107532");
  script_version("2022-08-09T10:11:17+0000");
  script_cve_id("CVE-2019-3923");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-12 14:55:00 +0000 (Tue, 12 Feb 2019)");
  script_tag(name:"creation_date", value:"2019-02-07 16:16:06 +0100 (Thu, 07 Feb 2019)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Tenable Nessus < 8.2.2 Stored XSS Vulnerability (TNS-2019-01)");

  script_tag(name:"summary", value:"Nessus is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stored cross-site scripting (XSS) vulnerability exists due to
  improper validation of user-supplied input before returning it to users.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker can exploit this
  vulnerability via a specially crafted request, to execute arbitrary script code in a user's
  browser session.");

  script_tag(name:"affected", value:"Nessus versions prior to version 8.2.2.");

  script_tag(name:"solution", value:"Update to version 8.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2019-01");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"8.2.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.2.2", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
