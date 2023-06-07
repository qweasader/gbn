##############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro InternScan Web Security Virtual Appliance 6.5 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:trendmicro:interscan_web_security_virtual_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106841");
  script_version("2021-09-10T11:01:38+0000");
  script_cve_id("CVE-2017-11396");
  script_tag(name:"last_modification", value:"2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-06-01 15:02:52 +0700 (Thu, 01 Jun 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-19 19:12:00 +0000 (Wed, 19 Aug 2020)");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Trend Micro InternScan Web Security Virtual Appliance 6.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl");
  script_mandatory_keys("trendmicro/IWSVA/detected");

  script_tag(name:"summary", value:"Trend Micro has released a new hot fix for Trend Micro InterScan Web
  Security Virtual Appliance (IWSVA) 6.5. This build resolves multiple vulnerabilities related to potential remote
  code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Version 6.5 before CP 1755 is known to be vulnerable.");

  script_tag(name:"solution", value:"Update to version 6.5 CP 1755 or newer.");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1117412");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (!build = get_kb_item("trendmicro/IWSVA/build"))
  exit(0);

if (version == "6.5" && int(build) < 1755) {
  report = report_fixed_ver(installed_version: version, installed_build: build,
                            fixed_version: "6.5", fixed_build: "1755");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
