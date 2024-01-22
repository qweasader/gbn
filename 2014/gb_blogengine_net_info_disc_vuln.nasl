# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803791");
  script_version("2023-12-22T16:09:03+0000");
  script_cve_id("CVE-2013-6953");
  script_tag(name:"last_modification", value:"2023-12-22 16:09:03 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-01-08 13:24:03 +0530 (Wed, 08 Jan 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("BlogEngine.NET 'sioc.axd' Information Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/553166");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64635");

  script_tag(name:"summary", value:"BlogEngine.NET is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check is it possible to
  read a configuration file.");

  script_tag(name:"insight", value:"The flaw is due to an improper access restriction to 'sioc.axd',
  which contains system configuration files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the target system and obtain valuable information such as access credentials.");

  script_tag(name:"affected", value:"BlogEngine.net version 2.8.0.0 and earlier.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

foreach dir (make_list_unique("/", "/blogengine", "/blog/blogengine", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  if(http_vuln_check(port:port, url:dir + "/", pattern:">BlogEngine\.NET<",
                     check_header:TRUE, usecache:TRUE)) {

    url = dir + "/sioc.axd";
    if(http_vuln_check(port:port, url:url, pattern:"sioc:Usergroup>",
       check_header:TRUE, extra_check:make_list(">BlogEngine\.NET", "sioc_id"))) {
      report = http_report_vuln_url(prt:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
