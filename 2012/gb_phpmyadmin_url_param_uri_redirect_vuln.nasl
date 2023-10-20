# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802607");
  script_version("2023-10-17T05:05:34+0000");
  script_cve_id("CVE-2011-1941");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-02-09 17:17:17 +0530 (Thu, 09 Feb 2012)");
  script_name("phpMyAdmin 'url' Parameter URI Redirection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47943");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67569");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-4.php");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to redirect users to
  arbitrary web sites and conduct phishing attacks.");
  script_tag(name:"affected", value:"phpMyAdmin version 3.4.0");
  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input to
  the 'url' parameter in url.php, which allows attackers to redirect a user to
  an arbitrary website.");
  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 3.4.1 or later.");
  script_tag(name:"summary", value:"phpMyAdmin is prone to URI redirection vulnerability.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

url = string("http://", get_host_name(), dir, "/ChangeLog");
req = http_get(item: string(dir, "/url.php?url=", url), port: port);
if(!isnull(req))
{
  pattern = string("Location: ", url);

  res = http_send_recv(port:port, data:req);
  if(!isnull(res))
  {
    if(res =~ "HTTP/1.. 302" && pattern >< res){
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
