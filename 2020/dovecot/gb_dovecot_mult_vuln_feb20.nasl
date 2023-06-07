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

CPE = "cpe:/a:dovecot:dovecot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112694");
  script_version("2021-07-08T11:00:45+0000");
  script_tag(name:"last_modification", value:"2021-07-08 11:00:45 +0000 (Thu, 08 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-02-13 09:58:21 +0000 (Thu, 13 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-20 07:15:00 +0000 (Thu, 20 Feb 2020)");

  script_cve_id("CVE-2020-7957", "CVE-2020-7046");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dovecot 2.3.9 < 2.3.9.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The IMAP and LMTP components in Dovecot mishandle snippet generation when many characters must be
  read to compute the snippet and a trailing > character exists.
  This causes a denial of service in which the recipient cannot read all of their messages.

  - lib-smtp in submission-login and lmtp in Dovecot mishandles truncated UTF-8 data in command parameters.");

  script_tag(name:"impact", value:"Successful exploitation would cause various system processes to be exhausted,
  leading into a denial of service and CPU resource exhaustion, or cause the mailbox to be permanently unaccessible.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dovecot versions 2.3.9 before 2.3.9.3.");

  script_tag(name:"solution", value:"Update to version 2.3.9.3 or later.");

  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2020-February/000430.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2020-February/000431.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.3.9", test_version2: "2.3.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.9.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
