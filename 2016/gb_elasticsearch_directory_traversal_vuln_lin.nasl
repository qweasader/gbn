###############################################################################
# OpenVAS Vulnerability Test
#
# Elasticsearch < 1.6.1 Multiple Vulnerabilities (Linux)
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

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808502");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2015-5531", "CVE-2015-5377");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-29 15:40:00 +0000 (Thu, 29 Mar 2018)");
  script_tag(name:"creation_date", value:"2016-06-28 18:11:01 +0530 (Tue, 28 Jun 2016)");
  script_name("Elasticsearch < 1.6.1 Multiple Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"Elasticsearch is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to:

  - an error in the snapshot API calls (CVE-2015-5531)

  - an attack that can result in remote code execution (CVE-2015-5377).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute code or read arbitrary files.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Elasticsearch version 1.0.0 through 1.6.0
  on Linux.");

  script_tag(name:"solution", value:"Update to Elasticsearch version 1.6.1,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75935");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536017/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!esPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!esVer = get_app_version(cpe:CPE, port:esPort)){
 exit(0);
}

if(version_in_range(version:esVer, test_version:"1.0.0", test_version2:"1.6.0"))
{
  report = report_fixed_ver(installed_version:esVer, fixed_version:"1.6.1");
  security_message(data:report, port:esPort);
  exit(0);
}
