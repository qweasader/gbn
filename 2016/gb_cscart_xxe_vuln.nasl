# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cs-cart:cs-cart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106398");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-11-18 10:07:02 +0700 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CS-Cart XXE Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cscart_detect.nasl");
  script_mandatory_keys("cs_cart/installed");

  script_tag(name:"summary", value:"CS-Cart is prone to an XML external entity (XXE) injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a XML External Entity injection (XXE) vulnerability in the Twigmo
  Addon and in the Amazon Payment Addon.");

  script_tag(name:"impact", value:"An unauthenticated attacker may read arbitrary files or conduct a denial
  of service attack.");

  script_tag(name:"solution", value:"Update to CS-Cart 4.4.2 or later which:

  - removes the vulnerable Twigmo Addon (deprecated)

  - fixes the XXE vulnerability in the Amazon Payment Addon.");

  script_xref(name:"URL", value:"http://docs.cs-cart.com/4.5.x/history/442.html#cs-cart-4-4-2-changelog");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40770/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

# TODO: Add a version check as soon as a fixed version is available
# For now just check if Twigmo Addon is enabled.
data = 'action=add_to_cart&data=CjwhRE9DVFlQRSB0ZXN0aW5neHhlIFs8IUVOVElUWSB4eGUgU1lTVEVNICdodHRwOi8vMTI3LjAu' +
       'MC4xOjgwJyA%2BXT4KPGRvY3VtZW50Pgo8a2lsbGl0PiZ4eGU7PC9raWxsaXQ%2BCjwvZG9jdW1lbnQ%2BCg%3D%3D&format=xml';

req = http_post_put_req(port: port, url: dir + "/index.php?dispatch=twigmo.post", data: data,
                        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req);

if ("twigmo_version" >< res && "<status><![CDATA[OK]]></status>" >< res) {
  security_message(port: port);
  exit(0);
}

exit(0);
