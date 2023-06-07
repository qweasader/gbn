##############################################################################
# OpenVAS Vulnerability Test
#
# HPE Operations Orchestration Remote Code Execution Vulnerability (hpesbgn03767)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:operations_orchestration";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813102");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2017-8994");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-09 02:29:00 +0000 (Thu, 09 Nov 2017)");
  script_tag(name:"creation_date", value:"2018-03-27 10:01:59 +0530 (Tue, 27 Mar 2018)");
  script_name("HPE Operations Orchestration RCE Vulnerability (hpesbgn03767)");

  script_tag(name:"summary", value:"HPE Operations Orchestration is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified error within the
  application.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attacker to execute
  arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"HPE Operations Orchestration versions prior to 10.80.");

  script_tag(name:"solution", value:"Update to version 10.80 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbgn03767en_us");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100588");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hpe_operations_orchestration_detect.nasl");
  script_mandatory_keys("hpe/operations/orchestration/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"10.80")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.80", install_path:path);
  security_message(port:port, data: report);
  exit(0);
}

exit(99);