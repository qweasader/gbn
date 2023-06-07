###############################################################################
# OpenVAS Vulnerability Test
#
# SugarCRM Multiple SQL Injection Vulnerabilities
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
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

CPE = "cpe:/a:sugarcrm:sugarcrm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812802");
  script_version("2021-10-11T12:37:27+0000");
  script_cve_id("CVE-2018-6308");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-11 12:37:27 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-12 18:37:00 +0000 (Mon, 12 Feb 2018)");
  script_tag(name:"creation_date", value:"2018-02-08 15:40:09 +0530 (Thu, 08 Feb 2018)");

  script_name("SugarCRM <= 6.5.26 Multiple SQLi Vulnerabilities");

  script_tag(name:"summary", value:"SugarCRM Community Edition is prone to multiple SQL injection
  (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the invalidated parameter '$track' of the
  '\modules\Campaigns\Tracker.php' file and the parameter '$clicked_url_key' of the
  '\modules\Campaigns\utils.php' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to
  manipulate the argument load_signed_id as part of a parameter that leads to an SQL injection
  vulnerability.");

  script_tag(name:"affected", value:"SugarCRM Community Edition 6.5.26 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.defensecode.com/advisories/DC-2018-01-011_SugarCRM_Community_Edition_Advisory.pdf");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_detect.nasl");
  script_mandatory_keys("sugarcrm/installed", "sugarcrm/edition");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

edition = get_kb_item("sugarcrm/edition");
if(edition != "CE")
  exit(0);

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"6.5.26")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);