# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11367");
  script_version("2023-09-12T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2020-09-22 10:18:28 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-1999-0636");

  script_name("Check for discard Service");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Useless services");
  script_dependencies("SHN_discard.nasl");
  script_mandatory_keys("discard/detected");

  script_tag(name:"summary", value:"The remote host is running a 'discard' service. This service
  typically sets up a listening socket and will ignore all the data which it receives.

  This service is unused these days, so it is advised that you disable it.");

  script_tag(name:"vuldetect", value:"Checks whether a discard service is exposed on the target
  host.");

  script_tag(name:"solution", value:"- Under Unix systems, comment out the 'discard' line in /etc/inetd.conf
  and restart the inetd process

  - Under Windows systems, set the following registry key to 0:
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpDiscard

  Then launch cmd.exe and type:

  net stop simptcp

  net start simptcp

  To restart the service.");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_kb_item( "discard/port" ) ) exit( 0 );

report = "The discard service was detected on the target host.";
security_message( data: report, port: port );
exit( 0 );
