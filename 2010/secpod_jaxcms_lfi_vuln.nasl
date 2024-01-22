# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900756");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-1043");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("JaxCMS 'index.php' Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38524");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11359");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to include
  and execute local files via directory traversal sequences and URL-encoded NULL bytes.");

  script_tag(name:"affected", value:"JaxCMS version 1.0 and prior");

  script_tag(name:"insight", value:"The flaw is due to error in 'index.php' which is not properly
  sanitizing user input passed to the 'p' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"JaxCMS is prone to local file inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/JaxCMS", "/jaxcms", "/", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if("JaxCMS" >< res) {
    ##  Platform independent Attack string
    req = http_get(item:string(dir, "/index.php?p=", vt_strings["lowercase"], "%00"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if("failed to open stream" >< res) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
