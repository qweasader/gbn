# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openmairie:opencatalogue";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902054");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1999");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("openMairie openCatalogue 'dsn[phptype]' LFI Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openmairie_prdts_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openmairie/open_catalogue/http/detected");

  script_tag(name:"insight", value:"Input passed to the parameter 'dsn[phptype]' in 'scr/soustab.php'
  is not properly verified before being used to include files.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"openMairie openCatalogue is prone to a local file inclusion
  (LFI) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include
  or disclose the contents of local files with the privileges of the web server.");

  script_tag(name:"affected", value:"OpenMairie openCatalogue version 1.024 and prior.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39688");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1051");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/opencatalogue-lfi.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/scr/soustab.php?dsn[phptype]=../../../../../../../../vt-rfi.txt";

req = http_get(port: port, item: url);
res = http_send_recv(port: port, data: req);

if ("/vt-rfi.txt/" >< res && "failed to open stream" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
