###############################################################################
# OpenVAS Vulnerability Test
#
# Wiser SIP Server Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804454");
  script_version("2022-04-14T11:24:11+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-05-20 16:32:39 +0530 (Tue, 20 May 2014)");
  script_name("Wiser SIP Server Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Wiser SIP Server is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check is it possible to read
the backup information.");
  script_tag(name:"insight", value:"Wiser contains a flaw that allow a remote attacker to gain access to
backup information by sending a direct request for the
/voip/sipserver/class/baixarBackup.php script.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
information without prior authentication.");
  script_tag(name:"affected", value:"Wiser SIP Server version 2.10");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126700/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67481");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

sipPort = http_get_port(default:80);

sipReq = http_get(item:"/voip/sipserver/login/", port:sipPort);
sipRes = http_keepalive_send_recv(port:sipPort, data:sipReq, bodyonly:TRUE);

if(sipRes && ">SIP Server<" >< sipRes)
{
  sipReq = http_get(item:"/voip/sipserver/class/baixarBackup.php", port:sipPort);
  sipRes = http_send_recv(port:sipPort, data:sipReq, bodyonly:FALSE);

  if ('radius.sql' >< sipRes && 'openser.sql' >< sipRes &&
      'Content-Description: File Transfer' >< sipRes)
  {
    security_message(port:sipPort);
    exit(0);
  }
}
