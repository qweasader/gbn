# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105198");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-02-10 17:03:19 +0100 (Tue, 10 Feb 2015)");
  script_name("FortiAnalyzer Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("fortinet/fortios/system_status");

  script_tag(name:"summary", value:"SSH login-based detection of FortiAnalyzer.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

system = get_kb_item("fortinet/fortios/system_status");
if( !system || "FortiAnalyzer" >!< system )
  exit( 0 );

set_kb_item( name:"fortianalyzer/system_status", value:system );
cpe = "cpe:/h:fortinet:fortianalyzer";

model = eregmatch( string:system, pattern:"Platform Full Name\s*:\s*(FortiAnalyzer-" + '[^ \r\n]+)' );

if( ! isnull( model[1] ) )
{
  mod = model[1];
  mod = chomp( mod );
  set_kb_item( name:"fortianalyzer/model", value:mod );
  cpe += '-' + tolower( mod );
}

vers = 'unknown';
version = eregmatch( string:system, pattern:"Version\s*:\sv([0-9.]++)" );

if( ! isnull( version[1] ) )
{
  ver = version[1];
  for( i = 0; i < strlen( ver ); i++ )
  {
    if( ver[i] == "." )
      continue;

    v += ver[ i ];

    if( i < ( strlen( ver ) - 1 ) )
      v += '.';
  }
  set_kb_item( name:"fortianalyzer/version", value:v );
  cpe += ':' + v;
  vers = v;
}

build = eregmatch( string:system, pattern:"-build([^ ]+)?" );
if( ! isnull( build[1] ) )
{
  build = ereg_replace( string:build[1], pattern:'^0', replace:"" );
  set_kb_item( name:"fortianalyzer/build", value:build );
}

patch = eregmatch( string:system, pattern:"Patch ([0-9]+)" );
if( ! isnull( patch[1] ) )
{
  set_kb_item( name:"fortianalyzer/patch", value:patch[1] );
}

register_product( cpe:cpe, location:"ssh", service:"ssh" );

report = 'Detected FortiAnalyzer (ssh)\n\n' +
         'Version: ' + vers + '\n';

if( mod )
  report += 'Model:   ' + mod + '\n';

if( ! isnull( build ) )
  report += 'Build:   ' + build + '\n';

report += 'CPE:     ' + cpe;

log_message( port:0, data:report );

exit( 0 );
