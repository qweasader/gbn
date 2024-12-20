# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114035");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-09-18 13:56:20 +0200 (Tue, 18 Sep 2018)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_name("Digital Watchdog Spectrum Default Credentials (HTTP)");
  script_dependencies("gb_digital_watchdog_spectrum_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 7001);
  script_mandatory_keys("digital_watchdog/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://customvideosecurity.com/blog/tag/default-password-axis/");

  script_tag(name:"summary", value:"The remote installation of Digital Watchdog Spectrum is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Digital Watchdog Spectrum is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Digital Watchdog Spectrum is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/h:digital_watchdog:spectrum";

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

creds = make_array("admin", "admin");

url = "/api/getCurrentUser";

foreach cred(keys(creds)) {
  req1 = http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                    "Accept", "application/json, text/plain, */*"));
  res1 = http_keepalive_send_recv(port: port, data: req1);

  #X-server-guid: {473cb4f0-82d2-bc40-9dbe-cf1eac5eae5c}
  #Digest realm="digitalwatchdog", nonce="57624355991e0", algorithm=MD5
  #Digest realm="AXIS_ACCC8E59BF16", nonce="cE7MlfV0BQA=3d81636877c1a2d7a335f9d39bb9e90a45396eeb", algorithm=MD5, qop="auth"
  info = eregmatch(pattern: 'X-server-guid: (\\{[^"]+\\}).*WWW-Authenticate: Digest realm="([^"]+)", nonce="([^"]+)", algorithm=MD5', string: res1);
  if(isnull(info[1]) || isnull(info[2]) || isnull(info[3])) continue;
  xguid = info[1];
  realm = info[2];
  nonce = info[3];

  #Digest authentication according to the standard showcased here: https://tools.ietf.org/html/rfc2617#section-3
  #In this specific case (this information is only found as admin on any host):
  #For url-based authentication and cookie-based authentication you need to calculate hash manually, using the following algorithm:
  #1. Get nonce and realm from server
  #2. Translate user's username to lower case
  #3. Check required method ('GET' for http-requests, 'PLAY' for rtsp)
  #4. ha1 = MD5(usename:realm:password)
  #5. ha2 = MD5(ha1:nonce:MD5(method:))
  #6. auth = base64(username:nonce:simplified_ha2)

  ha1 = hexstr(MD5(string(tolower(cred), ":", realm, ":", creds[cred])));
  ha2 = hexstr(MD5(string(ha1, ":", nonce, ":", hexstr(MD5(string("GET", ":"))))));
  auth = base64(str: string(tolower(cred), ":", nonce, ":", ha2));

  ha2_rtsp = hexstr(MD5(string(ha1, ":", nonce, ":", hexstr(MD5(string("PLAY", ":"))))));
  auth_rtsp = base64(str: string(tolower(cred), ":", nonce, ":", ha2_rtsp));

  #X-runtime-guid={083a3c1c-1f3e-4c52-8ef5-46562378830d}; Authorization=Digest; nonce=5769ef8249a60; realm=digitalwatchdog;
  #auth=YWRtaW46NTc2OWVmODI0OWE2MDo0OWMxM2I1YjFiN2E3MGQ5Mjk4YzcyMTExZmIyNDA0Mw%3D%3D; auth_rtsp=YWRtaW46NTc2OWVmODI0OWE2MDphZWQ5MzUwNjFhYzg5MThkMTk3MDIwZWIxODY2YWQwOA%3D%3D
  auth_header = 'X-runtime-guid=' + xguid + '; Authorization=Digest; nonce=' + nonce + '; realm=' + realm + '; auth=' + auth + '; auth_rtsp=' + auth_rtsp;

  req2 = http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                    "Accept", "application/json, text/plain, */*",
                                                                    "Cookie", auth_header));
  res2 = http_keepalive_send_recv(port: port, data: req2);

  if('{"error": "0"' >< res2 && '"reply": {"cryptSha512Hash":' >< res2) {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';
  }
}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
