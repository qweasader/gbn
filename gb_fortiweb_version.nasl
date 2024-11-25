# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105199");
  script_version("2024-11-15T15:55:05+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-15 15:55:05 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-02-10 17:03:19 +0100 (Tue, 10 Feb 2015)");
  script_name("Fortinet FortiWeb Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("fortinet/fortios/system_status");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/web-application-firewall/fortiweb");

  script_tag(name:"summary", value:"SSH login-based detection of Fortinet FortiWeb.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

system = get_kb_item("fortinet/fortios/system_status");
if( ! system || "FortiWeb" >!< system )
  exit( 0 );

cpe = "cpe:/a:fortinet:fortiweb";

model = eregmatch( string:system, pattern:"Version\s*:\s*(FortiWeb-[^ ]+).*" );

if( ! isnull( model[1] ) ) {
  mod = model[1];
  mod = chomp( mod );
  set_kb_item( name:"fortiweb/model", value:mod );
  concluded = "  " + model[0];
}

vers = "unknown";
install = "/";
version = eregmatch( string:system, pattern:"Version\s*:\s*FortiWeb-[^ ]* ([0-9.]+)," );

if( ! isnull( version[1] ) ) {
  ver = version[1];
  for( i = 0; i < strlen( ver ); i++ ) {
    if( ver[i] == "." )
      continue;

    v += ver[ i ];

    if( i < ( strlen( ver ) - 1 ) )
      v += ".";
  }
  set_kb_item( name:"fortiweb/version", value:v );
  cpe += ":" + v;
  vers = v;
  # nb: No need to add this to the "concluded" reporting as it is in the same line as the model
}

build = eregmatch( string:system, pattern:",build([^,]+)" );
if( ! isnull( build[1] ) ) {
  build = ereg_replace( string:build[1], pattern:"^0", replace:"" );
  set_kb_item( name:"fortiweb/build", value:build );
  # nb: No need to add this to the "concluded" reporting as it is in the same line as the version/model
}

patch = eregmatch( string:system, pattern:"Patch ([0-9]+)" );
if( ! isnull( patch[1] ) ) {
  ptch = patch[1];
  set_kb_item( name:"fortiweb/patch", value:ptch );
  if( concluded )
    concluded += '\n';
  concluded += "  " + patch[0];
}

register_product( cpe:cpe, location:install, service:"ssh-login", port:0 );

if( mod )
  extra = "  Model: " + mod;

if( ! concluded )
  concluded = system;

report = build_detection_report( app:"Fortinet FortiWeb",
                                 version:vers,
                                 install:install,
                                 cpe:cpe,
                                 build:build,
                                 patch:ptch,
                                 extra:extra,
                                 concluded:concluded );

log_message( port:0, data:report );

exit( 0 );
