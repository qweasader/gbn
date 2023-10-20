# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105337");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-08-28 16:12:01 +0200 (Fri, 28 Aug 2015)");
  script_name("Intel Active Management Technology (AMT) WebUI Interface Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Intel Active Management Technology (AMT)
  WebUI Interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 16992);
  script_mandatory_keys("IAMT/banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:16992 );
banner = http_get_remote_headers( port:port );
if( ! banner )
  exit( 0 );

if( ! concl = egrep( string:banner, pattern:"Server: Intel\(R\) Active Management Technology", icase:TRUE ) )
  exit( 0 );

concl = chomp( concl );

set_kb_item( name:"intel_amt/installed", value:TRUE );
set_kb_item( name:"intel_amt/detected", value:TRUE );
set_kb_item( name:"intel_amt/http/detected", value:TRUE );

vers = "unknown";
install = "/";
cpe = "cpe:/o:intel:active_management_technology_firmware";

# nb: Despite NIST is using a `cpe:/o` CPE no OS reporting/registration is done for this as the
# underlying OSes like Windows might be not reported.

version = eregmatch( pattern:'Server: Intel\\(R\\) Active Management Technology ([0-9.]+)', string:banner );
if( ! isnull( version[1] ) ) {
  vers = version[1];
  concl = version[0];
  cpe += ":" + vers;
}

register_product( cpe:cpe, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"Intel Active Management Technology (AMT)",
                                          version:vers,
                                          install:install,
                                          cpe:cpe,
                                          concluded:concl ),
             port:port );

exit( 0 );
