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

CPE = "cpe:/a:cisco:unified_communications_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106647");
  script_version("2024-07-26T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-07-26 05:05:35 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-03-14 09:51:18 +0700 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 13:58:42 +0000 (Thu, 25 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-5638");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Communications Manager Apache Struts2 Jakarta Multipart Parser File Upload Code Execution Vulnerability (cisco-sa-20170310-struts2)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_cucm_consolidation.nasl");
  script_mandatory_keys("cisco/cucm/detected");

  script_tag(name:"summary", value:"Cisco Unified Communications Manager is prone to a
  vulnerability in Apache Struts2.");

  script_tag(name:"insight", value:"On March 6, 2017, Apache disclosed a vulnerability in the
  Jakarta multipart parser used in Apache Struts2 that could allow an attacker to execute commands
  remotely on the targeted system using a crafted Content-Type header value.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170310-struts2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]\.[0-9]\.[0-9]+"))
  exit(0);

if (version =~ "^11\.0\.1\.10000" || version =~ "^11\.5\.1\.10000") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
