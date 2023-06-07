# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801766");
  script_version("2023-05-05T09:09:19+0000");
  script_cve_id("CVE-2011-0456");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");

  script_name("OTRS < 2.3.5 Command Execution Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute an
  arbitrary OS command with the privileges of OTRS on the server where it is installed.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to certain unspecified input is not properly
  sanitised before being used. This can be exploited to inject and execute shell commands.");

  script_tag(name:"solution", value:"Update to version 2.3.5 or later.");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to a command
  execution vulnerability.");

  script_tag(name:"affected", value:"OTRS versions prior to 2.3.5.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38507/");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN73162541/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000019.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"2.3.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.3.5");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
