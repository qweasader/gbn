###############################################################################
# OpenVAS Vulnerability Test
#
# F3Site 'GLOBALS[nlang]' Parameter Multiple Local File Include Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800415");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4435");
  script_name("F3Site 'GLOBALS[nlang]' Parameter Multiple Local File Include Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54908");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37408");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10536");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to obtain sensitive
  information or execute arbitrary code on the vulnerable Web Server.");

  script_tag(name:"affected", value:"F3Site 2009 and prior.");

  script_tag(name:"insight", value:"The flaw is due to error in 'mod/poll.php' and 'mod/new.php' which
  are not properly sanitising user supplied input data via 'GLOBALS[nlang]'
  parameter.");

  script_tag(name:"solution", value:"Upgrade to F3Site 2010 or later.");

  script_tag(name:"summary", value:"F3Site is prone to multiple local file include Vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://dhost.info/compmaster/index.php");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach path (make_list_unique("/", "/F3Site/SYSTEM", "/F3Site", http_cgi_dirs(port:port))) {

  if(path == "/") path = "";

  res = http_get_cache(item:path + "/index.php", port:port);

  if("F3Site" >< res) {
    if(!version = eregmatch(pattern:"F3Site ([0-9.]+)",string:res))
      exit(0);

    if(version_is_less_equal(version:version[1], test_version:"2009")) {
      report = report_fixed_ver(installed_version:version[1], vulnerable_range:"Less than or equal to 2009");
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
