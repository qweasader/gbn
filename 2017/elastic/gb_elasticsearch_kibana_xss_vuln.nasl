###############################################################################
# OpenVAS Vulnerability Test
#
# Elastic Kibana Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812277");
  script_version("2021-10-12T09:28:32+0000");
  script_cve_id("CVE-2017-11481");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-12 09:28:32 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 17:30:00 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-12-20 15:20:49 +0530 (Wed, 20 Dec 2017)");
  script_name("Elastic Kibana Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Elastic Kibana is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation
  of user supplied input via URL fields.");

  script_tag(name:"impact", value:"Successful exploitation will lead an attacker
  to execute arbitrary script code and obtain sensitive information from or
  perform destructive actions on behalf of other Kibana users.");

  script_tag(name:"affected", value:"Elastic Kibana versions prior to 6.0.1
  and 5.6.5.");

  script_tag(name:"solution", value:"Update to Elastic Kibana version
  6.0.1 or 5.6.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!kibanaPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!infos = get_app_version_and_location( cpe:CPE, port:kibanaPort, exit_no_version:TRUE)) exit(0);
kibanaVer = infos['version'];
path = infos['location'];

if(kibanaVer =~ "^(5\.6)")
{
  if(version_is_less(version:kibanaVer, test_version:"5.6.5")){
    fix = "5.6.5";
  }
}
else if(kibanaVer =~ "^(6\.0)")
{
  if(version_is_less(version:kibanaVer, test_version:"6.0.1")){
    fix = "6.0.1";
  }
}

if(fix)
{
  report = report_fixed_ver( installed_version:kibanaVer, fixed_version:fix, install_path:path );
  security_message(data:report, port:kibanaPort);
  exit(0);
}
exit(0);
