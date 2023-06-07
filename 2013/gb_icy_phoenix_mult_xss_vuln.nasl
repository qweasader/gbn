###############################################################################
# OpenVAS Vulnerability Test
#
# Icy Phoenix Multiple Cross-Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803952");
  script_version("2022-04-25T14:50:49+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-10-08 15:21:12 +0530 (Tue, 08 Oct 2013)");
  script_name("Icy Phoenix Multiple Cross-Site Scripting Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
  cookie-based authentication credentials.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is able
  to read the string or not.");

  script_tag(name:"insight", value:'An error exists in the application which fails to properly sanitize user-supplied
  input to "subject" parameter before using it.');
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Icy Phoenix is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"affected", value:"Icy Phoenix version 2.0, Lower versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62722");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79115");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123446");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/117197");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/icyphoenix", "/ip", http_cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(res && (egrep(pattern:"Powered by.*Icy Phoenix.*phpBB", string:res)))
  {
    url = dir + "/index.php?>'" + '"><script>alert(01234567891);</script>=';

    match = "<script>alert\(01234567891\);</script>";
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:match))
    {
      report = http_report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
