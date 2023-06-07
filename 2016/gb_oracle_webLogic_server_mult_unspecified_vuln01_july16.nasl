###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle WebLogic Server Multiple Unspecified Vulnerabilities-01 July16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807351");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-3445", "CVE-2016-3499", "CVE-2016-3510", "CVE-2016-3586",
                "CVE-2015-7501", "CVE-2016-5531", "CVE-2016-3505");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-07-20 18:03:42 +0530 (Wed, 20 Jul 2016)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Oracle WebLogic Server Multiple Unspecified Vulnerabilities-01 July16");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified vulnerabilities in Oracle Fusion Middleware.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
  service condition, execute arbitrary code and gain elevated privileges on the affected system.");

  script_tag(name:"affected", value:"Oracle WebLogic Server versions 10.3.6.0, 12.1.3.0, 12.2.1.0.");

  script_tag(name:"solution", value:"Apply the patches from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2016-2881720.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92003");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92019");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92013");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92016");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93730");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93708");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_equal(version:version, test_version:"10.3.6.0.0") ||
   version_is_equal(version:version, test_version:"12.1.3.0.0") ||
   version_is_equal(version:version, test_version:"12.2.1.0.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See advisory");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
