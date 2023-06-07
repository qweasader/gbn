# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900480");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0922");
  script_name("PostgreSQL 'CVE-2009-0922' Denial of Service Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "secpod_postgresql_detect_win.nasl");
  script_mandatory_keys("postgresql/detected");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488156");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34090");
  script_xref(name:"URL", value:"http://archives.postgresql.org/pgsql-bugs/2009-02/msg00172.php");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause stack consumption or
  denial of service through mismatched encoding conversion requests.");

  script_tag(name:"affected", value:"PostgreSQL versions before 8.3.7, 8.2.13, 8.1.17, 8.0.21, and 7.4.25");

  script_tag(name:"insight", value:"This flaw is due to failure in converting a localized error message to the
  client-specified encoding.");

  script_tag(name:"solution", value:"Upgrade to respective version below,
  PostgreSQL 8.3.7 or 8.2.13 or 8.1.17 or 8.0.21 or 7.4.25.");

  script_tag(name:"summary", value:"PostgreSQL Server is prone to denial of service vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"8.3", test_version2:"8.3.6") ||
   version_in_range(version:version, test_version:"8.2", test_version2:"8.2.12") ||
   version_in_range(version:version, test_version:"8.1", test_version2:"8.1.16") ||
   version_in_range(version:version, test_version:"8.0", test_version2:"8.0.20") ||
   version_in_range(version:version, test_version:"7.4", test_version2:"7.4.24")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.3.7/8.2.13/8.1.17/8.0.21/7.4.25", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
