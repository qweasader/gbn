# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804470");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-4018", "CVE-2014-4019", "CVE-2014-4154", "CVE-2014-4155");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-25 12:28:41 +0530 (Wed, 25 Jun 2014)");
  script_name("ZTE WXV10 W300 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"ZTE WXV10 W300 router is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted default credential via HTTP GET request and check whether it
  is able to read rom-0 or not.");

  script_tag(name:"insight", value:"- The 'admin' account has a password of 'admin', which is publicly known and
   documented. This allows remote attackers to trivially gain privileged access
   to the device.

  - Flaw in /basic/home_wan.htm that is triggered as the device exposes the
   device password in the source of the page when a user authenticates to the
   device.

  - The HTTP requests to /Forms/tools_admin_1 do not require multiple steps,
   explicit confirmation, or a unique token when performing certain sensitive
   actions.

  - The rom-0 backup file contains sensitive information such as the router
   password. There is a disclosure in which anyone can download that file
   without any authentication by a simple GET request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trivially gain privileged
  access to the device, execute arbitrary commands and gain access to arbitrary files.");

  script_tag(name:"affected", value:"ZTE ZXV10 W300");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33803");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68082");
  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2014/01/23/zte-zxv10-w300-router-multiple-vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ZXV10_W300/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

zPort = http_get_port(default:80);

zBanner = http_get_remote_headers(port:zPort);
if('WWW-Authenticate: Basic realm="ZXV10 W300"' >!< zBanner) exit(0);

zreq = http_get( item:'/rom-0', port:zPort);
zres = http_keepalive_send_recv( port:zPort, data:zreq, bodyonly:FALSE );

## http_vuln_check() is not working
if("dbgarea" >< zres && "spt.dat" >< zres)
{
  security_message(port:zPort);
  exit(0);
}

exit(99);
