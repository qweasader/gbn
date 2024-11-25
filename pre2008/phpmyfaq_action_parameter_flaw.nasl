# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14258");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2004-2255");

  script_name("phpMyFAQ action parameter arbitrary file disclosure vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to phpMyFAQ 1.3.13 or newer.");

  script_tag(name:"summary", value:"The remote web server contains a PHP script that permits information
disclosure of local files.

The version of phpMyFAQ on the remote host contains a flaw that may lead to an unauthorized information
disclosure.  The problem is that user input passed to the 'action' parameter is not properly verified before
being used to include files, which could allow a remote attacker to view any accessible file on the system,
resulting in a loss of confidentiality.");

  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/052004.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10374");
  script_xref(name:"URL", value:"http://www.phpmyfaq.de/advisory_2004-05-18.php");
  script_xref(name:"OSVDB", value:"6300");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.3.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.13");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
