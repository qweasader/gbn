# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804431");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-17 12:16:13 +0530 (Thu, 17 Apr 2014)");
  script_name("Horde Webmail 'url' Parameter Open Redirect Vulnerability");

  script_tag(name:"summary", value:"Horde Webmail is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it redirects to the
  malicious websites.");

  script_tag(name:"insight", value:"The flaw exists because the application does not validate the 'url'
  parameter upon submission to the /horde/util/go.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to create a specially
  crafted URL, that if clicked, would redirect a victim from the intended legitimate web site to an arbitrary web
  site of the attacker's choosing.");

  script_tag(name:"affected", value:"Horde Webmail version 5.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32638");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125953");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("horde_detect.nasl");
  script_mandatory_keys("horde/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/util/go.php?url=http://www.horde.org/apps/webmail";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv( port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && res =~ "refresh: 0; URL=http://www\.horde\.org/apps/webmail"){
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
