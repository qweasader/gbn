# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113325");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-16 13:45:55 +0200 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-20718");

  script_name("Pydio <= 8.2.1 PHO Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pydio_detect.nasl");
  script_mandatory_keys("pydio/installed");

  script_tag(name:"summary", value:"Pydio is prone to a PHP Object Injection Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists due to pydio interpreting any string that
  starts with $phpserial$ as serialized and then procedding to deserialize it.
  During this, an attacker could inject POP gadget chains and eventually make
  a call to call_user_func().");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary commands
  on the target machine.");
  script_tag(name:"affected", value:"Pydio through version 8.2.1.");
  script_tag(name:"solution", value:"Update to version 8.2.2.");

  script_xref(name:"URL", value:"https://blog.ripstech.com/2018/pydio-unauthenticated-remote-code-execution/");

  exit(0);
}

CPE = "cpe:/a:pydio:pydio";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "8.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );