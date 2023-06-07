# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:oracle:oraclebi_discoverer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803131");
  script_version("2023-05-16T09:08:27+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-16 09:08:27 +0000 (Tue, 16 May 2023)");
  script_tag(name:"creation_date", value:"2012-12-19 12:18:56 +0530 (Wed, 19 Dec 2012)");
  script_name("OracleBI Discoverer <= 10.1.2.48.18 'node' XSS Vulnerability");
  script_xref(name:"URL", value:"http://ur0b0r0x.blogspot.com/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118808/oraclebi-xss.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_oraclebi_discoverer_detect.nasl");
  script_mandatory_keys("OracleBIDiscoverer/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"OracleBI Discoverer version 10.1.2.48.18 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user supplied input
  to the 'node' parameter in '/discoverer/app/explorer', which allows attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"OracleBI Discoverer is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"10.1.2.48.18")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
