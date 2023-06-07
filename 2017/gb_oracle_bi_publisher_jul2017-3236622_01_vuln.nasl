###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle BI Publisher Multiple Unspecified Vulnerabilities-01 (jul2017-3236622-jul2018-4258247)
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

CPE = "cpe:/a:oracle:business_intelligence_publisher";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811247");
  script_version("2022-04-13T11:57:07+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-19 17:26:23 +0530 (Wed, 19 Jul 2017)");

  script_cve_id("CVE-2017-10025", "CVE-2017-10024", "CVE-2017-10028", "CVE-2017-10029",
                "CVE-2017-10030", "CVE-2017-10059", "CVE-2018-2900");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle BI Publisher Multiple Unspecified Vulnerabilities - 01 (cpujul2017, cpujul2018)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_bi_publisher_detect.nasl");
  script_mandatory_keys("oracle/bi_publisher/detected");

  script_tag(name:"summary", value:"Oracle BI Publisher is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to unspecified errors in the 'Mobile Service',
  'Web Server', 'Layout Tools' and 'BI Publisher Security' components of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to have impact on
  confidentiality and integrity.");

  script_tag(name:"affected", value:"Oracle BI Publisher version 11.1.1.7.0.");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2017.html#AppendixFMW");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99697");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99723");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99724");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99738");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99743");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2018.html#AppendixFMW");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "11.1.1.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
