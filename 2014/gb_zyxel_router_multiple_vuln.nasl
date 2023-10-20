# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804471");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-25 12:28:41 +0530 (Wed, 25 Jun 2014)");
  script_name("ZyXEL ADSL Router Multiple Vulnerabilities");

  script_tag(name:"summary", value:"ZyXEL ADSL Router is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted default credential via HTTP GET request and check whether it
  is able to read cookie or not.");

  script_tag(name:"insight", value:"- The 'Forms/rpAuth_1' does not validate input to an arbitrary parameter
    before returning it to users.

  - ZyXEL contains a flaw that is due to a lack of protection mechanisms in
    the login form.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trivially gain privileged
  access to the device, execute arbitrary commands and gain access to arbitrary files.");

  script_tag(name:"affected", value:"ZyXEL P660RT2 EE");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127179");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/103");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RomPager/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

zPort = http_get_port(default:80);

zBanner = http_get_remote_headers(port:zPort);
if('Server: RomPager' >!< zBanner) exit(0);

url ="/Forms/rpAuth_1?=%3Cbody%20onload=alert%28document.cookie%29%3E";

if(http_vuln_check(port:zPort, url:url, check_header:TRUE,
   pattern: "<body onload=alert\(document.cookie\)><",
   extra_check:"> Message <"))
{
  security_message(port:zPort);
  exit(0);
}

exit(99);
