#############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro InterScan Messaging Security Virtual Appliance (IMSVA) Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:trendmicro:interscan_messaging_security_virtual_appliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811007");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-7896");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-25 00:43:00 +0000 (Tue, 25 Apr 2017)");
  script_tag(name:"creation_date", value:"2017-04-25 12:30:07 +0530 (Tue, 25 Apr 2017)");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Trend Micro InterScan Messaging Security Virtual Appliance (IMSVA) Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.nasl");
  script_mandatory_keys("trend_micro/imsva/detected", "trend_micro/imsva/build");

  script_tag(name:"summary", value:"Trend Micro InterScan Messaging Security Virtual Appliance is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist as the appliance fails to
  sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of current user, conduct
  cross-site scripting (XSS) and XML External Entity (XXE) attacks.");

  script_tag(name:"affected", value:"Trend Micro InterScan Messaging Virtual Appliance (IMSVA) 9.1 before CP 1644.");

  script_tag(name:"solution", value:"Update to version 9.1 CP 1644 or later.");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1116821-security-bulletin-trend-micro-interscan-messaging-security-virtual-appliance-imsva-9-1-multiple-v#");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97938");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(!build = get_kb_item("trend_micro/imsva/build"))
  exit(0);

if((version == "9.1") && (version_is_less(version:build, test_version:"1644"))) {
  report = report_fixed_ver(installed_version:version, installed_build:build,
                            fixed_version:"9.1", fixed_build:"1644");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
