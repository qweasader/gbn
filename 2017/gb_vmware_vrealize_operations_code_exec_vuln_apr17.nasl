# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:vmware:vrealize_operations_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811006");
  script_version("2022-08-22T10:11:10+0000");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"creation_date", value:"2017-04-21 10:42:44 +0530 (Fri, 21 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:40:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2015-6934");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware vRealize Operations RCE Vulnerability (VMSA-2015-0009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_vrealize_operations_manager_http_detect.nasl");
  script_mandatory_keys("vmware/vrealize/operations_manager/detected");

  script_tag(name:"summary", value:"VMware vRealize Operations is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a deserialization error involving Apache
  Commons-collections and a specially constructed chain of classes exists.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code in the context of current user.");

  script_tag(name:"affected", value:"VMware vRealize Operations 6.x prior to version 6.2.");

  script_tag(name:"solution", value:"Update to version 6.2 or later.");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0009.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79648");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up:"6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
