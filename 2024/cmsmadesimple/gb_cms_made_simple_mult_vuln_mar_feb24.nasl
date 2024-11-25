# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128001");
  script_version("2024-06-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-06-05 05:05:26 +0000 (Wed, 05 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-03-08 12:00:00 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2024-1527", "CVE-2024-1528", "CVE-2024-1529", "CVE-2024-27622",
                "CVE-2024-27623", "CVE-2024-27625");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("CMS Made Simple <= 2.2.20 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-1527: Unrestricted file upload allows an authenticated user to bypass the security
  measures of the upload functionality and potentially create a remote execution of commands via
  webshell.

  - CVE-2024-1528: Not sufficient encode user-controlled input, results in a cross-site scripting
  (XSS) through /admin/moduleinterface.php, in multiple parameters. This could allow a remote
  attacker to send a specially crafted JavaScript payload to an authenticated user and partially
  hijack their browser session.

  - CVE-2024-1529: Not sufficient encode user-controlled input, results in a cross-site scripting
  (XSS) through /admin/adduser.php, in multiple parameters. This could allow a remote
  attacker to send a specially crafted JavaScript payload to an authenticated user and partially
  hijack their browser session.

  - CVE-2024-27622: Remote code execution where authenticated users with administrative privileges
  can inject and execute arbitrary PHP code due to inadequate sanitization of user-supplied input
  in the Code section of the module.

  - CVE-2024-27623: Server-Side Template Injection vulnerability in Design Manager
  when editing Breadcrumbs.

  - CVE-2024-27625: Cross Site Scripting in File Manager module of the admin panel due to
  inadequate sanitization of user input in the New directory field.");

  script_tag(name:"affected", value:"CMS Made Simple version 2.2.20 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 04th July, 2024.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-cms-made-simple");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/177243/CMS-Made-Simple-2.2.19-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://github.com/capture0x/CMSMadeSimple2");
  script_xref(name:"URL", value:"https://github.com/capture0x/CMSMadeSimple");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "2.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
