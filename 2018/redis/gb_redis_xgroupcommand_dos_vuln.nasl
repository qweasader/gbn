# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:redis:redis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813440");
  script_version("2021-09-29T11:39:12+0000");
  script_cve_id("CVE-2018-12453");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-09-29 11:39:12 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-14 17:37:00 +0000 (Tue, 14 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-06-18 17:33:41 +0530 (Mon, 18 Jun 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Redis 'xgroupCommand' function DoS Vulnerability");

  script_tag(name:"summary", value:"Redis is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a type confusion in the
  'xgroupCommand' function in 't_stream.c' script in redis-server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Redis versions before 5.0 RC2.");

  script_tag(name:"solution", value:"Update to version 5.0 RC2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://github.com/antirez/redis/commit/c04082cf138f1f51cedf05ee9ad36fb6763cafc6");
  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/34a56d575030682f6c564553c53b82b5");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");
  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less_equal(version:version, test_version: "4.0.10")) {
  fix = "5.0 RC2";
}

##5.0 RC1 == 4.9.101
else if(version == "4.9.101") {
  fix = "5.0 RC2";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);