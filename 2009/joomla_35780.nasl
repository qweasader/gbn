# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100333");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-03 12:50:27 +0100 (Tue, 03 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Remote File Upload Vulnerability And Information Disclosure Weakness");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35780");
  script_xref(name:"URL", value:"http://developer.joomla.org/security/news/301-20090722-core-file-upload.html");
  script_xref(name:"URL", value:"http://developer.joomla.org/security/news/302-20090722-core-missing-jexec-check.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/505231");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"solution", value:"The vendor has released updates to address the issues. Please see the
  references for more information.");

  script_tag(name:"summary", value:"Joomla! is prone to a remote file-upload vulnerability and an information
  disclosure weakness.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to disclosure sensitive information, or
  upload arbitrary code and execute it in the context of the webserver process. This may facilitate unauthorized
  access or privilege escalation, other attacks are also possible.");

  script_tag(name:"affected", value:"Joomla! 1.5.x versions prior to 1.5.13 are vulnerable.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.5", test_version2: "1.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.13");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);