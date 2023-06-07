###############################################################################
# OpenVAS Vulnerability Test
#
# TCW PHP Album 'album' Parameter Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801231");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_cve_id("CVE-2010-2714", "CVE-2010-2715");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("TCW PHP Album 'album' Parameter Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41382");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60079");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1696");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14203");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to run HTML or
  JavaScript code in the context of the affected site, or exploit latent
  vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"TCW PHP Album Version 1.0");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input passed via the 'album' parameter to 'index.php', which allows attackers
  to perform cross-site scripting, SQL-injection, and HTML-Injection attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"TCW PHP Album is prone to multiple input validation vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/phpalbum", "/tcwphpalbum", "/", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir,"/index.php"), port:port);

  if("<TITLE>My Pics</TITLE>" >< res && "tcwphpalbum" >< res) {
    if(http_vuln_check(port:port, url:string(dir,"/index.php?album=<script>",
                       "alert('", vt_strings["lowercase"], "')</script>"),
                       pattern:"<script>alert\('" + vt_strings["lowercase"] + "'\)</script>",
                       check_header:TRUE)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
