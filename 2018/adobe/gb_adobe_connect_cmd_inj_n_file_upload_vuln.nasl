###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Connect Command Injection And Unrestricted File Upload Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813038");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2018-4921", "CVE-2018-4923");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-22 17:16:00 +0000 (Fri, 22 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-03-15 11:20:29 +0530 (Thu, 15 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Command Injection And Unrestricted File Upload Vulnerabilities");

  script_tag(name:"summary", value:"Adobe Connect is prone to a command injection and unrestricted file upload vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An unrestricted SWF file upload.

  - An OS command-injection vulnerability because it fails to properly sanitize
    user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject and execute arbitrary commands within the context of the
  affected application. This may aid in further attacks and upload arbitrary files
  to the affected computer.");

  script_tag(name:"affected", value:"Adobe Connect versions 9.7 and earlier");

  script_tag(name:"solution", value:"Upgrade to Adobe Connect version 9.7.5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb18-06.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103393");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103391");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_mandatory_keys("adobe/connect/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!acPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:acPort, exit_no_version:TRUE)) exit(0);
acVer = infos['version'];
acPath = infos['location'];

if(version_is_less_equal(version:acVer, test_version:"9.7"))
{
  report = report_fixed_ver(installed_version:acVer, fixed_version:"9.7.5", install_path:acPath);
  security_message(data:report, port:acPort);
  exit(0);
}
exit(0);
