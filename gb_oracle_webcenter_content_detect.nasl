###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle WebCenter Content Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811709");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-08-18 12:44:35 +0530 (Fri, 18 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle WebCenter Content Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Oracle WebCenter Content.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

owPort = http_get_port(default:80);

sndReq = http_get(item:"/cs/login/login.htm", port:owPort);
res = http_keepalive_send_recv(port:owPort, data:sndReq);

if(res && ">Oracle WebCenter Content Sign In<" >< res &&
   (res =~ "Copyright.*Oracle") || ("ORACLETEXTSEARCH" >< res && "ORACLE_QUERY_OPTIMIZER" >< res))
{
  owVer = "unknown";
  version = "unknown";
  version_url = "/_ocsh/help/state?navSetId=help_for_translation_MA_user_en_MA" +
                "_user_html_l10n_adtuh_hlpbk&navId=1";

  sndReq = http_get(item:version_url, port:owPort);
  res = http_keepalive_send_recv(port:owPort, data:sndReq);

  if(res =~ "HTTP/1.. 302" && "Location: http" >< res)
  {
    newverUrl =  eregmatch(pattern:"Location: (http.*&destination=)", string:res);
    newverUrl = newverUrl[1];
    if(newverUrl)
    {
      sndReq = http_get(item:newverUrl, port:owPort);
      res = http_keepalive_send_recv(port:owPort, data:sndReq);
    }
  }

  if(res =~ "HTTP/1.. 200 OK" && "Oracle WebCenter Content Help<" >< res &&
  ("Dynamic Converter Online Help" >< res || "Dynamic Converter<" >< res))
  {
    version = eregmatch( pattern:"([0-9A-Za-z]+) ([A-Za-z]+ [0-9]+ )?\(([0-9.]+)\) - Oracle WebCenter Content Help</title>", string:res);
    if(version[2] && version[1] && version[3])
    {
      owVer = version[3];
      version = version[1] + " " + version[2] + owVer ;
    } else if(version[3] && version[1])
    {
      owVer = version[3];
      version = version[1] + " " + owVer ;
    }
    if(owVer){
      set_kb_item(name:"Oracle/WebCenter/Content/Version", value:owVer);
    }
  }

  set_kb_item(name:"Oracle/WebCenter/Content/Installed", value:TRUE);

  cpe = build_cpe(value:owVer, exp:"^([0-9.]+)", base:"cpe:/a:oracle:webcenter_content:");
  if(!cpe)
    cpe = 'cpe:/a:oracle:webcenter_content';

  register_product(cpe:cpe, location:"/", port:owPort, service:"www");
  log_message(data: build_detection_report(app: "Oracle WebCenter Content",
                                           version:owVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:version),
                                           port:owPort);
  exit(0);
}
exit(0);
