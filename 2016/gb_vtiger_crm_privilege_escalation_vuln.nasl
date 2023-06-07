###############################################################################
# OpenVAS Vulnerability Test
#
# VTiger CRM Privilege Escalation and Unrestricted File Upload Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:vtiger:vtiger_crm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808752");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-4834", "CVE-2016-1713");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-02 01:29:00 +0000 (Mon, 02 Apr 2018)");
  script_tag(name:"creation_date", value:"2016-08-05 19:05:51 +0530 (Fri, 05 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VTiger CRM Privilege Escalation and Unrestricted File Upload Vulnerability");

  script_tag(name:"summary", value:"VTiger CRM is prone to a privilege escalation and unrestricted file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to:

  - 'modules/Users/actions/Save.php' script does not properly restrict user-save actions

  - Settings_Vtiger_CompanyDetailsSave_Action class in 'modules/Settings/Vtiger/actions/CompanyDetailsSave.php'
  allosw uploading a crafted image file with an executable extension.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to execute arbitrary code or to create or modify user accounts via unspecified vectors.");

  script_tag(name:"affected", value:"VTiger CRM before version 6.5.0.");

  script_tag(name:"solution", value:"Upgrade to vTiger CRM version 6.5.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000126.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92076");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vtigerPort = get_app_port(cpe:CPE))
  exit(0);

if(!vtigerVer = get_app_version(cpe:CPE, port:vtigerPort))
  exit(0);

if(version_is_less_equal(version:vtigerVer, test_version:"6.4.0")) {
  report = report_fixed_ver(installed_version:vtigerVer, fixed_version:"6.5.0");
  security_message(data:report, port:vtigerPort);
  exit(0);
}

exit(99);
