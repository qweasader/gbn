# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106546");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2017-01-27 12:28:21 +0700 (Fri, 27 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Haraka SMTP Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_mandatory_keys("smtp/banner/available");

  script_xref(name:"URL", value:"https://haraka.github.io/");

  script_tag(name:"summary", value:"Detection of Haraka SMTP Server

  The script sends a connection request to the server and attempts to detect Haraka SMTP server and its version
  number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port(default:25);

banner = smtp_get_banner(port: port);
quit = get_kb_item("smtp/fingerprints/" + port + "/quit_banner");
ehlo = get_kb_item("smtp/fingerprints/" + port + "/ehlo_banner");

if (("ESMTP Haraka" >< banner || "Haraka is at your service" >< ehlo) && "Have a jolly good day" >< quit) {

  install = port + "/tcp";
  version = "unknown";

  vers = eregmatch(pattern: "ESMTP Haraka ([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "haraka/version", value: version);
  }

  set_kb_item(name: "haraka/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:haraka:haraka:");
  if (!cpe)
    cpe = "cpe:/a:haraka:haraka";

  register_product(cpe: cpe, location: install, port: port, service: "smtp");
  log_message(data: build_detection_report(app: "Haraka", version: version, install: install, cpe: cpe,
                                           concluded: vers[0]),
              port: port);
}

exit(0);
