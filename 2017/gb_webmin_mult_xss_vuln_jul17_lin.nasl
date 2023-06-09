###############################################################################
# OpenVAS Vulnerability Test
#
# Webmin Multiple XSS Vulnerabilities - July17 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811502");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-9313");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-10 17:03:00 +0000 (Mon, 10 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-07-11 15:47:13 +0530 (Tue, 11 Jul 2017)");
  script_name("Webmin Multiple XSS Vulnerabilities - July17 (Linux)");

  script_tag(name:"summary", value:"Webmin is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an improper
  validation of 'sec' parameter to 'view_man.cgi' script, the 'referers'
  parameter to 'change_referers.cgi' script and the 'name' parameter to
  'save_user.cgi' script.");

  script_tag(name:"impact", value:"Successful exploitation will lead an attacker
  to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Webmin versions before 1.850");

  script_tag(name:"solution", value:"Upgrade to Webmin version 1.850 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/Jul/3");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99373");
  script_xref(name:"URL", value:"http://www.webmin.com/changes.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("webmin.nasl", "os_detection.nasl");
  script_mandatory_keys("webmin/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wmport = get_app_port(cpe:CPE)){
 exit(0);
}

if(!wmver = get_app_version(cpe:CPE, port:wmport)){
 exit(0);
}

if(version_is_less(version:wmver, test_version:"1.850"))
{
  report = report_fixed_ver(installed_version:wmver, fixed_version:"1.850");
  security_message(data:report, port:wmport);
  exit(0);
}
exit(0);
