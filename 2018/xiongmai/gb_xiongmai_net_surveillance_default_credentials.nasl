# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114039");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-10-09 19:58:10 +0200 (Tue, 09 Oct 2018)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_name("Xiongmai Net Surveillance Default Credentials (HTTP)");
  script_dependencies("gb_xiongmai_net_surveillance_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xiongmai/net_surveillance/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.sec-consult.com/en/blog/2018/10/millions-of-xiongmai-video-surveillance-devices-can-be-hacked-via-cloud-feature-xmeye-p2p-cloud/");
  script_xref(name:"URL", value:"https://krebsonsecurity.com/tag/xc3511/");

  script_tag(name:"summary", value:"The remote installation of Xiongmai Net Surveillance is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Xiongmai Net Surveillance is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Xiongmai Net Surveillance is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

CPE = "cpe:/a:xiongmai:net_surveillance";

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

creds = make_array("admin", "",
                   "default", "tluafed",
                   "root", "xc3511");

url = "/Login.htm";

foreach username(keys(creds)) {

  password = creds[username];
  auth_cookie = "NetSuveillanceWebCookie=%7B%22username%22%3A%22" + username + "%22%7D";
  data = "command=login&username=" + username + "&password=" + password;

  req = http_post_put_req(port: port,
                      url: url,
                      data: data,
                      add_headers: make_array("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                                              "Cookie", auth_cookie));

  res = http_keepalive_send_recv(port: port, data: req);

  if("var g_SoftWareVersion=" >< res && 'failedinfo="Log in failed!"' >!< res) {
    VULN = TRUE;
    if(!password)
      password = "<no/empty password>";
    report += '\n' + username + ':' + password;
  }
}

if(VULN) {
  report = 'It was possible to login with the following default credentials (username:password):\n' + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
