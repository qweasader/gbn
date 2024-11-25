# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105814");
  script_version("2024-11-15T05:05:36+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-15 05:05:36 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-07-19 09:58:46 +0200 (Tue, 19 Jul 2016)");
  script_name("Fortinet FortiManager Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("fortinet/fortios/system_status");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/management/fortimanager");

  script_tag(name:"summary", value:"SSH login-based detection of Fortinet FortiManager.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

system = get_kb_item( "fortinet/fortios/system_status" );
if( ! system || "FortiManager" >!< system )
  exit( 0 );

cpe = "cpe:/h:fortinet:fortimanager";
vers = "unknown";

m = eregmatch( pattern:'Platform Full Name\\s*:\\s*FortiManager-([^ \r\n]+)', string:system );
if( ! isnull( m[1] ) ) {
  model = m[1];
  set_kb_item( name:"fortimanager/model", value:model );
}

if( version = get_kb_item( "forti/FortiOS/version" ) ) {
  vers = version;
  cpe += ":" + vers;
  set_kb_item( name:"fortimanager/version", value:TRUE );
}

rep_vers = vers;

if( build = get_kb_item( "forti/FortiOS/build" ) ) {
  set_kb_item( name:"fortimanager/build", value:build );
  rep_vers += " Build " + build;
}

register_product( cpe:cpe, location:"ssh", service:"ssh" );

report = build_detection_report( app:"FortiManager", version:rep_vers, install:"ssh", cpe:cpe, concluded:system );
log_message( port:0, data:report );
exit( 0 );
