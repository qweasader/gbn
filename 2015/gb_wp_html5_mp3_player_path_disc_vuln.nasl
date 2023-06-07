###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Html5 Mp3 Player 'playlist.php' Path Disclosure Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805120");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2014-9177");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2015-01-09 12:56:08 +0530 (Fri, 09 Jan 2015)");
  script_name("WordPress Html5 Mp3 Player 'playlist.php' Path Disclosure Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'Html5 Mp3 Player with Playlist' is prone to path disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is disclosing installation path or not.");

  script_tag(name:"insight", value:"Flaw is triggered when a remote attacker
  sends a direct request for the /html5plus/playlist.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to discloses the software's installation path resulting in a
  loss of confidentiality.");

  script_tag(name:"affected", value:"WordPress HTML5 MP3 Player with
  Playlist Free plugin before 2.7");

  script_tag(name:"solution", value:"Upgrade to version 2.7 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/98988");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71512");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129286");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/html5-mp3-player-with-playlist/changelog");
  script_xref(name:"URL", value:"http://h4x0resec.blogspot.in/2014/11/wordpress-html5-mp3-player-with.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/html5-mp3-player-with-playlist/html5plus/playlist.php";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<b>Fatal error</b>:  Call to a member function get_row\(\)",
   extra_check:make_list("on line <b>18</b>","html5plus/playlist.php"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
