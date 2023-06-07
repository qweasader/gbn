# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:pureftpd:pure-ftpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143322");
  script_version("2021-08-12T09:01:18+0000");
  script_tag(name:"last_modification", value:"2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-01-07 09:35:08 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-08 04:15:00 +0000 (Sat, 08 Feb 2020)");

  script_cve_id("CVE-2019-20176", "CVE-2020-9274", "CVE-2020-9365");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Pure-FTPd <= 1.0.49 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("sw_pure-ftpd_detect.nasl");
  script_mandatory_keys("pure-ftpd/detected");

  script_tag(name:"summary", value:"Pure-FTPd is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Pure-FTPd is prone to multiple vulnerabilities:

  - Stack exhaustion issue in the listdir function in ls.c (CVE-2019-20176)

  - Uninitialized pointer vulnerability in the diraliases linked list (CVE-2020-9274)

  - Insufficient length check in pure_strcmp()

  - Out-of-bounds (OOB) read has been detected in the pure_strcmp function in utils.c (CVE-2020-9365)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Pure-FTPd version 1.0.49 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/jedisct1/pure-ftpd/commit/aea56f4bcb9948d456f3fae4d044fd3fa2e19706");
  script_xref(name:"URL", value:"https://github.com/jedisct1/pure-ftpd/commit/8d0d42542e2cb7a56d645fbe4d0ef436e38bcefa");
  script_xref(name:"URL", value:"https://github.com/jedisct1/pure-ftpd/commit/bf6fcd4935e95128cf22af5924cdc8fe5c0579da");
  script_xref(name:"URL", value:"https://github.com/jedisct1/pure-ftpd/commit/36c6d268cb190282a2c17106acfd31863121b58e");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.0.49")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
