# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108286");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-4905");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-07 10:54:29 +0100 (Tue, 07 Nov 2017)");

  script_name("Apache ActiveMQ 'CVE-2011-4905' Denial of Service Vulnerability (Linux)");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_apache_activemq_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/activemq/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.html");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows remote
  attackers to cause a Denial of Service (file-descriptor exhaustion and broker crash or hang).");

  script_tag(name:"affected", value:"Apache ActiveMQ version before 5.6.0.");

  script_tag(name:"solution", value:"Update to Apache ActiveMQ version 5.6.0, or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.6.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.6.0" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
