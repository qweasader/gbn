# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105802");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-07 16:59:41 +0200 (Thu, 07 Jul 2016)");
  script_name("QRadar Detection");

  script_tag(name:"summary", value:"The script performs SSH  based detection of QRadar");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("qradar/version");
  exit(0);
}

include("host_details.inc");

if( ! version = get_kb_item( "qradar/version" ) ) exit( 0 );

cpe = 'cpe:/a:ibm:qradar_security_information_and_event_manager:' + version;

# example version 7.3.1.20180720020816
register_product( cpe:cpe, location:'ssh' );
report = build_detection_report( app:'QRadar', version:version, install:'ssh', cpe:cpe );
log_message( port:0, data:report );

exit( 0 );
