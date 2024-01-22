# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900460");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0645");
  script_name("Jaws CMS Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7976");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33607");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48476");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"affected", value:"Jaws CMS 0.8.8 and prior");

  script_tag(name:"insight", value:"This flaw is due to an error in file 'index.php' in 'language'
  parameter which lets the attacker execute local file inclusion attacks.");

  script_tag(name:"solution", value:"Upgrade to the latest version 0.8.9.");

  script_tag(name:"summary", value:"Jaws CMS is prone to a Directory Traversal Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute local file inclusion
  attacks and gain sensitive information about the remote system directories where Jaws CMS runs.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("version_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

jawsPort = http_get_port(default:80);

if(!http_can_host_php(port:jawsPort)){
  exit(0);
}

foreach path(make_list_unique("/", http_cgi_dirs(port:jawsPort)))
{

  if(path == "/") path = "";

  request = http_get(item: path + "/jaws/index.php", port:jawsPort);
  response = http_keepalive_send_recv(port:jawsPort, data:request);

  if(response == NULL){
    exit(0);
  }
  if("Jaws" >< response)
  {
    version = eregmatch(pattern:"Jaws ([0-9.]+)", string:response);
    if(version[1] != NULL)
    {
      if(version_is_less_equal(version:version[1], test_version:"0.8.8"))
      {
        report = report_fixed_ver(installed_version:version[1], vulnerable_range:"Less than or equal to 0.8.8");
        security_message(port: jawsPort, data: report);
        exit(0);
      }
    }
  }
}

exit(99);
