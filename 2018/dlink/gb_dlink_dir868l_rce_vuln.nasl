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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112252");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2018-04-09 12:25:00 +0200 (Mon, 09 Apr 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-22 13:17:00 +0000 (Tue, 22 May 2018)");

  script_cve_id("CVE-2018-9284");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR-868L StarHub Firmware Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-868L devices are prone to a pre-authenticated remote
  code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability is an unauthenticated buffer overflow that
  occurs when the affected router parses authentication requests.");

  script_tag(name:"impact", value:"Upon successful exploitation, an attacker could then run arbitrary
  code under the privilege of a web service.");

  script_tag(name:"affected", value:"D-Link DIR-868L with customized Singapore StarHub firmware.");

  script_tag(name:"solution", value:"Upgrade to version 1.21SHCb03 or later.");

  script_xref(name:"URL", value:"http://www.dlink.com.sg/dir-868l/#firmware");
  script_xref(name:"URL", value:"https://www.fortinet.com/blog/threat-research/fortiguard-labs-discovers-vulnerability-in--d-link-router-dir868.html");

  exit(0);
}

CPE = "cpe:/o:d-link:dir-868l_firmware";

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if ("shc" >< version && version_is_less(version: version, test_version: "1.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.21SHCb03");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
