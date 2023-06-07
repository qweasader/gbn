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

CPE = "cpe:/a:apache:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808106");
  script_version("2022-06-01T10:19:27+0000");
  script_tag(name:"last_modification", value:"2022-06-01 10:19:27 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"creation_date", value:"2016-05-18 09:39:48 +0530 (Wed, 18 May 2016)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");

  script_cve_id("CVE-2016-2167", "CVE-2016-2168");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Subversion Multiple Vulnerabilities (May 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apache_subversion_detect.nasl");
  script_mandatory_keys("apache/subversion/detected");

  script_tag(name:"summary", value:"Apache Subversion is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A flaw that will cause a null pointer dereference and a segmentation fault with certain invalid
  request headers in server module 'mod_authz_svn'.

  - An error in the canonicalize_username function in svnserve/cyrus_auth.c, when Cyrus SASL
  authentication is used.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause a
  denial of service and to authenticate and bypass intended access restrictions.");

  script_tag(name:"affected", value:"Apache Subversion version before 1.8.16 and 1.9.x before
  1.9.4.");

  script_tag(name:"solution", value:"Update to version 1.8.16, 1.9.4 or later.");

  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2016-2167-advisory.txt");
  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2016-2168-advisory.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.0", test_version_up: "1.8.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.9.0", test_version_up: "1.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
