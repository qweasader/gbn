# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105861");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Multiple Vendors 'securitydbData.xml' Information Disclosure");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2712");
  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX200584");

  script_tag(name:"vuldetect", value:"Try to read securitydbData.xml.");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"summary", value:"It is possible to obtain credentials via a direct request to conf/securitydbData.xml.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-09 14:38:38 +0200 (Tue, 09 Aug 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9090);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:9090 );

url = '/conf/securitydbData.xml';

if( http_vuln_check( port:port,
                     url:url,
                     pattern:'<AUTHORIZATION-DATA>',
                     extra_check: make_list( "<DATA ownername=", "password=" ) ) )
{
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );

