###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle WebLogic Server Multiple Unspecified Vulnerabilities (cpujul2017-3236622-cpuoct2018-4428296)
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

CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811245");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-10137", "CVE-2017-10152", "CVE-2018-2902");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-19 13:53:23 +0530 (Wed, 19 Jul 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Oracle WebLogic Server Multiple Unspecified Vulnerabilities (cpujul2017-3236622, cpuoct2018-4428296)");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple unspecified errors in the 'JNDI',
  'Console' and 'Web Container' components of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"Oracle WebLogic Server versions 10.3.6.0 and 12.1.3.0.");

  script_tag(name:"solution", value:"See the referenced advisories for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99634");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101351");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105654");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version( cpe:CPE, nofork:TRUE ))
  exit(0);

affected = make_list('10.3.6.0.0', '12.1.3.0.0');

foreach af (affected) {
  if( version == af) {
    report = report_fixed_ver(installed_version:version, fixed_version:"See advisory");
    security_message(data:report, port:0);
    exit(0);
  }
}

exit(99);
