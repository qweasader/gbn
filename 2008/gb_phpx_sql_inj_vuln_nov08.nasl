###############################################################################
# OpenVAS Vulnerability Test
#
# PHPX news_id SQL Injection Vulnerability - Nov08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800134");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5000");
  script_name("PHPX news_id SQL Injection Vulnerability - Nov08");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32564");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23033");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6996");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"affected", value:"PHPX Version 3.5.16 and prior on all running platform.");

  script_tag(name:"insight", value:"The flaw is due to sql commands with uppercase characters passed
  with the news_id parameter to includes/news.inc.php which is not properly sanitised before being used.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"PHPX is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary sql commands.

  NOTE: Vulnerability exists only when magic_quotes_gpc is disabled.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

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

foreach dir( make_list_unique( "/phpx", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir + "/index.php"), port:port);
  if(!rcvRes) continue;

  if(rcvRes =~ "Powered by.+PHPX")
  {
    phpxVer = eregmatch(pattern:"PHPX ([0-9.]+)", string:rcvRes);
    if(phpxVer != NULL)
    {
      if(version_is_less_equal(version:phpxVer[1], test_version:"3.5.16")){
        security_message(port:port);
      }
    }
    exit(0);
  }
}

exit(99);
