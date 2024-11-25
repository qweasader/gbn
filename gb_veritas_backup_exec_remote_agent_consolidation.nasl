# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170161");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2022-08-02 12:09:24 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Veritas Backup Exec Remote Agent Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_veritas_backup_exec_remote_agent_ndmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_veritas_backup_exec_remote_agent_smb_login_detect.nasl",
                        "gsf/gb_veritas_backup_exec_remote_agent_ssh_login_detect.nasl");

  script_mandatory_keys("veritas/backup_exec_remote_agent/detected");

  script_tag(name:"summary", value:"Consolidation of Veritas Backup Exec Remote Agent detections.");

  script_xref(name:"URL", value:"https://www.veritas.com/protection/backup-exec");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if( ! get_kb_item( "veritas/backup_exec_remote_agent/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "smb-login", "ndmp", "ssh-login" ) ) {

  install_list = get_kb_list( "veritas/backup_exec_remote_agent/" + source + "/*/installs" );

  if( ! install_list )
    continue;

  install_list = sort( install_list );

  foreach install( install_list ) {
    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 4 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    app      = infos[1];
    install  = infos[2];
    version  = infos[3];
    concl    = infos[4];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:veritas:backup_exec_remote_agent:" );
    if( ! cpe )
      cpe = "cpe:/a:veritas:backup_exec_remote_agent";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:app, version:version, install:install, cpe:cpe,
                                      concluded:concl );
  }
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
