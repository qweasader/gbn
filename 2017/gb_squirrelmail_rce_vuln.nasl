# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:squirrelmail:squirrelmail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106785");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-04-21 17:09:27 +0200 (Fri, 21 Apr 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_cve_id("CVE-2017-7692", "CVE-2018-8741");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("SquirrelMail < 1.4.23 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("squirrelmail_detect.nasl");
  script_mandatory_keys("squirrelmail/installed");

  script_tag(name:"summary", value:"SquirrelMail is prone to authenticated remote code execution
  (RCE) and directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SquirrelMail allows:

  - post-authentication remote code execution via a sendmail.cf file that is mishandled in a popen call.
  It's possible to exploit this vulnerability to execute arbitrary shell commands on the remote server.

  - uploading a mail attachment a temporary file is generated on the server that the client later references
  when sending the mail. The filename is not sanitized in any way, so by passing a filename of the form
  '../../../../some_path/some_filename' one can use this to attach arbitrary files from the server that can
  be accessed by the PHP process to a mail.");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary shell commands or
  read files from the filesystem.");

  script_tag(name:"affected", value:"SquirrelMail 1.4.22 and prior as well as the trunk version
  (before r14650).");

  script_tag(name:"solution", value:"Source-Code patches for both issues are available in the linked references.");

  script_xref(name:"URL", value:"https://www.wearesegment.com/research/Squirrelmail-Remote-Code-Execution.html");
  script_xref(name:"URL", value:"https://insinuator.net/2018/03/squirrelmail-full-disclosure-troopers18/");
  script_xref(name:"URL", value:"https://legalhackers.com/advisories/SquirrelMail-Exploit-Remote-Code-Exec-CVE-2017-7692-Vuln.html");
  script_xref(name:"URL", value:"https://gist.github.com/hannob/3c4f86863c418930ad08853c1109364e");
  script_xref(name:"URL", value:"https://sourceforge.net/p/squirrelmail/code/14650/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.4.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See reference");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);