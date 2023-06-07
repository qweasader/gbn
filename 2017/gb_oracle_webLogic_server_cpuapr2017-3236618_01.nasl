###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle WebLogic Server Multiple Vulnerabilities-01 (cpuapr2017-3236618)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810748");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-5638", "CVE-2016-1181", "CVE-2017-3506");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)");
  script_tag(name:"creation_date", value:"2017-04-19 14:58:02 +0530 (Wed, 19 Apr 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Oracle WebLogic Server Multiple Vulnerabilities-01 (cpuapr2017-3236618)");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to some unspecified error in the 'Samples (Struts 2)' and
  'Web Services' sub-component within Oracle WebLogic Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary commands.");

  script_tag(name:"affected", value:"Oracle WebLogic Server versions 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1 and 12.2.1.2.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97884");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

affected = make_list('10.3.6.0.0', '12.1.3.0.0', '12.2.1.0.0', '12.2.1.2.0', '12.2.1.1.0');

foreach af (affected) {
  if( version == af) {
    report = report_fixed_ver(installed_version:version, fixed_version:"See advisory");
    security_message(data:report, port:0);
    exit(0);
  }
}

exit(99);
