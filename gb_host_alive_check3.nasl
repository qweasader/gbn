# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108217");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-17 11:18:02 +0200 (Thu, 17 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Mark host as dead if going offline (failed ICMP ping) during scan - Phase 3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_dependencies("gb_host_alive_check2.nasl", "toolcheck.nasl", "global_settings.nasl",
                      "os_detection.nasl"); # To avoid launching it directly at the beginning of the ACT_GATHER_INFO phase
  script_mandatory_keys("global_settings/mark_host_dead_failed_icmp", "Tools/Present/ping");

  script_tag(name:"summary", value:"This plugin checks the target host in the phase 3 of a scan
  and marks it as 'dead' to the scanner if it is not answering to an ICMP ping anymore.

  NOTE: This plugin/behavior is disabled by default and needs to be enabled within the
  'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) of the scan config in use.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! cmd = get_kb_item( "Tools/Present/ping/bin" ) )
  exit( 0 );

i = 0;
ping_args = make_list();
ping_args[i++] = cmd;

if( extra_cmd = get_kb_item( "Tools/Present/ping/extra_cmd" ) )
  ping_args[i++] = extra_cmd;

ping_args[i++] = "-c 3";
ping_args[i++] = get_host_ip();

ping = pread( cmd:cmd, argv:ping_args, cd:TRUE );
if( "3 packets transmitted, 0 received" >< ping || "3 packets transmitted, 0 packets received" >< ping ) { #nb: inetutils vs. iputils
  log_message( port:0, data:"Target host seems to be suspended or disconnected from the Network. It was marked as 'dead' to the scanner and the scan was aborted." );
  register_host_detail( name:"dead", value:1 );
  set_kb_item( name:"Host/dead", value:TRUE );
}

exit( 0 );
