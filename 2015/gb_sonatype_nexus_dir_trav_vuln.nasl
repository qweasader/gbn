# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sonatype:nexus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805325");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-9389");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-20 13:00:12 +0530 (Tue, 20 Jan 2015)");
  script_name("Sonatype Nexus OSS/Pro Directory Traversal Vulnerability -Jan15");

  script_tag(name:"summary", value:"Nexus OSS/Pro is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain unspecified input is not properly
  verified before being used to read files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose sensitive information.");

  script_tag(name:"affected", value:"Nexus OSS/Pro versions prior to 2.11.1-01");

  script_tag(name:"solution", value:"Upgrade to Nexus OSS/Pro version 2.11.1-01
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61134");
  script_xref(name:"URL", value:"http://www.sonatype.org/advisories/archive/2014-12-23-Nexus/");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sonatype_nexus_detect.nasl");
  script_mandatory_keys("nexus/installed");
  script_require_ports("Services/www", 8081);
  script_xref(name:"URL", value:"http://www.sonatype.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!nexusVer = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_is_less(version:nexusVer, test_version:"2.11.1.01"))
{
 report = 'Installed version: ' + nexusVer + '\n' +
          'Fixed version:     2.11.1-01'  + '\n';

  security_message(port:http_port, data:report);
  exit(0);
}
