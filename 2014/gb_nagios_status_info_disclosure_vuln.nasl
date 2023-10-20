# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804247");
  script_version("2023-07-27T05:05:09+0000");
  script_cve_id("CVE-2013-2214");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-17 18:31:41 +0530 (Mon, 17 Mar 2014)");
  script_name("Nagios status.cgi Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Nagios is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
able to read the string or not.");
  script_tag(name:"insight", value:"The flaw exists in status.cgi which fails to restrict access to all service
groups");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
information.");
  script_tag(name:"affected", value:"Nagios version 4.0 before 4.0 beta4 and 3.x before 3.5.1.");
  script_tag(name:"solution", value:"Upgrade to version Nagios version 4.0 beta4, 3.5.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q3/54");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60814");
  script_xref(name:"URL", value:"http://tracker.nagios.org/view.php?id=456");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/cgi-bin/status.cgi?servicegroup=all&style=grid';

req = http_get(item:url,  port:http_port);
res = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

if(res && "Status Grid For All Service Groups" >< res && "Current Network Status" >< res)
{
  security_message(http_port);
  exit(0);
}
