# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16229");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Tiki Wiki CMS Groupware Multiple Unspecified Remote Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"http://tiki.org/art102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12328");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple unspecified
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"These flaws may allow an attacker to execute arbitrary PHP script
  code on the hosting web server.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( egrep( pattern:"(0\.|1\.[0-7]\.|1\.8\.[0-5][^0-9]|1\.9 RC(1|2|3|3\.1)([^.]|[^0-9]))", string:vers ) ) {
   report = report_fixed_ver( installed_version:vers, fixed_version:"See vendor advisory" );
   security_message( port:port, data:report );
   exit( 0 );
}

exit( 99 );
