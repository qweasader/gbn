# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apachefriends:xampp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804774");
  script_version("2024-06-18T05:05:55+0000");
  script_tag(name:"last_modification", value:"2024-06-18 05:05:55 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-10-10 11:43:07 +0530 (Fri, 10 Oct 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-2586");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XAMPP < 1.8.2 Local Write Access Vulnerability (Oct 2014) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xampp_http_detect.nasl");
  script_mandatory_keys("xampp/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"XAMPP is prone to an arbitrary file download vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The /xampp/lang.php script does not properly handling
  WriteIntoLocalDisk method granting write access to the lang.tmp file to unprivileged users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to manipulate
  the file and execute arbitrary script or HTML code.");

  script_tag(name:"affected", value:"XAMPP version 1.8.1 and probably prior.");

  script_tag(name:"solution", value:"Update to version 1.8.2 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/87499");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/28654");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123407");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "/";

## Before Updating lang.tmp get the content in it
## to revert it back after updation
req = http_get(item: dir + "/lang.tmp", port: port);
langtmp = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

url = dir + "/lang.php?WriteIntoLocalDisk";

## Send the Request to update lang.tmp
if (http_vuln_check(port: port, url: url, pattern:"HTTP.*302 Found")) {
  if (http_vuln_check(port: port, url: dir + "/lang.tmp", check_header: TRUE, pattern: "WriteIntoLocalDisk")) {
    ## Send the Request to update lang.tmp
    if (http_vuln_check(port: port, url: dir + "/lang.php?" + langtmp, pattern:"HTTP.*302 Found")) {
      url = dir + "/lang.tmp";
      if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: langtmp,
                          check_nomatch:"WriteIntoLocalDisk")) {
        report = http_report_vuln_url(port: port, url: url);
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(99);
