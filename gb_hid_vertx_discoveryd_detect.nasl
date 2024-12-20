# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141137");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-04 12:33:52 +0700 (Mon, 04 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HID VertX Detection (discoveryd)");

  script_tag(name:"summary", value:"Detection of HID VertX Access Control Devices.

The script sends a connection request to the server and attempts to detect HID VertX Access Control Devices and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 4050, 4070);

  script_xref(name:"URL", value:"https://www.hidglobal.com/products/controllers");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port(default: 4070, ipproto: "udp");

soc = open_sock_udp(port);
if (!soc)
  exit(0);

query = 'discover;013;';

send(socket: soc, data: query);
recv = recv(socket: soc, length: 512);

close(soc);

if (recv =~ "^discovered;") {
  version = "unknown";

  set_kb_item(name: "hid_vertx/detected", value: TRUE);

  data = split(recv, sep: ";", keep: FALSE);

  for (i=0; i<max_index(data); i++) {
    # MAC
    if (i == 2) {
      mac = data[i];
      register_host_detail(name: "MAC", value: mac, desc: "gb_hid_vertx_discoveryd_detect.nasl");
      replace_kb_item(name: "Host/mac_address", value: mac);
      extra += '\nMAC Address:    ' + mac;
    }

    # Name
    if (i == 3)
      extra += '\nName:           ' + data[i];

    # Internal IP
    if (i == 4)
      extra += '\nInternal IP:    ' + data[i];

    # Model
    if (i == 6) {
      model = data[i];
      set_kb_item(name: "hid_vertx/model", value: model);
    }

    # Firmware
    if (i == 7)
      version = data[i];

    if (i == 8)
      extra += '\nBuild Date:     ' + data[i];
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:hid:vertx:");
  if (!cpe)
    cpe = "cpe:/h:hid:vertx";

  service_register(port: port, proto: "discoveryd", ipproto: "udp");
  register_product(cpe: cpe, location: port + "/udp", port: port, proto: "udp", service: "discoveryd");

  log_message(data: build_detection_report(app: "HID VertX " + model, version: version, cpe: cpe, extra: extra),
              port: port, proto: "udp");
  exit(0);
}

exit(0);
