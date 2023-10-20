# SPDX-FileCopyrightText: 2003 k-otik.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mambo-foundation:mambo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11441");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7135");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Mambo Site Server 4.0.10 XSS");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2003 k-otik.com");
  script_dependencies("mambo_detect.nasl", "cross_site_scripting.nasl");
  script_mandatory_keys("mambo_cms/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to a newer version.");

  script_tag(name:"summary", value:"An attacker may use the installed version of Mambo Site Server to
  perform a cross site scripting attack on this host.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=search&searchword=<script>alert(document.cookie);</script>";
req = http_get(item:url, port:port);
resp = http_keepalive_send_recv(port:port, data:req);

if(!resp)
  exit(0);

if(resp =~ "HTTP/1\.. 200" && "<script>alert(document.cookie);</script>" >< resp) {
  security_message(port);
  exit(0);
}

exit(99);
