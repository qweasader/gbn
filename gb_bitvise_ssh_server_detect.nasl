# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813383");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-04 12:52:08 +0530 (Mon, 04 Jun 2018)");
  script_name("Bitvise SSH Server Detection");

  script_tag(name:"summary", value:"Detection of running version of
  Bitvise SSH Server.

  This script sends connection request and try to ensure the presence of
  Bitvise SSH Server.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/bitvise/ssh_server/detected");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);
server_banner = ssh_get_serverbanner(port:port);

if(server_banner && server_banner =~ "SSH.*Bitvise SSH Server \(WinSSHD\)")
{
  btVer = "unknown";
  install = port + "/tcp";
  set_kb_item(name:"BitviseSSH/Server/Installed", value:TRUE);

  btVer = eregmatch(pattern:"Bitvise SSH Server \(WinSSHD\) ([0-9.]+)", string:server_banner);
  if(btVer[1]) {
    set_kb_item(name:"BitviseSSH/Server/Version", value:btVer[1]);
    btVer = btVer[1];
  }

  cpe = build_cpe(value:btVer, exp:"^([0-9.]+)", base:"cpe:/a:bitvise:winsshd:");
  if (!cpe)
    cpe = "cpe:/a:bitvise:winsshd";

  register_product(cpe:cpe, location:install, port:port, service:"ssh");

  log_message(data:build_detection_report(app:"Bitvise SSH Server",
                                          version:btVer,
                                          install:install,
                                          cpe:cpe,
                                          concluded:server_banner),
                                          port:port);
}

exit(0);
