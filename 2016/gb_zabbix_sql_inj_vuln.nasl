# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106179");
  script_version("2022-02-23T09:58:00+0000");
  script_tag(name:"last_modification", value:"2022-02-23 09:58:00 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-08-17 11:04:27 +0700 (Wed, 17 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_cve_id("CVE-2016-10134");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zabbix 2.2.x, 3.0.x SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zabbix_http_detect.nasl");
  script_mandatory_keys("zabbix/detected");

  script_tag(name:"summary", value:"Zabbix is prone to a SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Zabbix suffers from a remote SQL injection vulnerability due to
  a failure to sanitize input in the toggle_ids array in the latest.php page.");

  script_tag(name:"impact", value:"An authenticated attacker (or guest user) is able to gain full
  access to the database. This would allow an attacker to escalate their privileges to a power
  user, compromise the database, or execute commands on the underlying database operating system.

  Because of the functionalities Zabbix offers, an attacker with admin privileges (depending on the
  configuration) can execute arbitrary OS commands on the configured Zabbix hosts and server. This
  results in a severe impact to the monitored infrastructure.

  Although the attacker needs to be authenticated in general, the system could also be at risk if
  the adversary has no user account. Zabbix offers a guest mode which provides a low privileged
  default account for users without password. If this guest mode is enabled, the SQL injection
  vulnerability can be exploited unauthenticated.");

  script_tag(name:"affected", value:"Zabbix version 2.2.x and 3.0.x.");

  script_tag(name:"solution", value:"Update to version 2.2.14, 3.0.4 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40237/");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-11023");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^2\.2") {
  if (version_is_less(version: version, test_version: "2.2.14")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.2.14");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^3\.0") {
  if (version_is_less(version: version, test_version: "3.0.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.0.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
