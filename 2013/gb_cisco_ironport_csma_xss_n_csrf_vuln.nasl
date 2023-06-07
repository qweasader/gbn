###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Content Security Management Appliance XSS and CSRF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cisco:content_security_management_appliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803754");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-3395", "CVE-2013-3396");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-09-04 11:53:49 +0530 (Wed, 04 Sep 2013)");
  script_name("Cisco Content Security Management Appliance XSS and CSRF Vulnerabilities");

  script_tag(name:"summary", value:"Cisco Content Security Management Appliance is prone to cross site scripting and cross site request forgery vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to latest version of Cisco CSMA.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The lack of output escaping in the default error 500 page. When an exception
  occurs in the application, the error description contains user unvalidated
  input from the request.

  - The lack of input validation on job_name, job_type, appliances_options and
  config_master parameters which are then printed unscapped on job_name,
  old_job_name, job_type, appliance_lists and config_master fields.

  - The CSRFKey is not used in some areas of the application.");

  script_tag(name:"affected", value:"Cisco Content Security Management Appliance (SMA) 8.1 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site.");

  script_xref(name:"URL", value:"http://1337day.com/exploit/21168");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60829");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60919");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122955");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=29844");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-3396");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/cisco-ironport-cross-site-request-forgery-cross-site-scripting");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_csma_version.nasl");
  script_mandatory_keys("cisco_csm/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"8.1.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);