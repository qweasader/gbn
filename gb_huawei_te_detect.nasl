# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141255");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-02 10:43:45 +0200 (Mon, 02 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei TE Device Detection (Telnet)");

  script_tag(name:"summary", value:"Telnet based detection of Huawei TE (Telepresence and
  Video Conferencing Endpoints) devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 5000);
  script_mandatory_keys("telnet/huawei/te/detected");

  script_xref(name:"URL", value:"https://e.huawei.com/uk/products/cloud-communications/telepresence-video-conferencing");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");
include("telnet_func.inc");

port = telnet_get_port(default: 5000);

banner = telnet_get_banner(port: port);
if (! banner || banner == "")
  exit(0);

banner = bin2string(ddata: banner, noprint_replacement: ' ');

if (banner =~ "Huawei TE[0-9]0") {
  version = "unknown";
  model = "TE Unknown Model";
  cpe_model = "te_unknown_model";

  #Huawei TE30@ TE30 V100R001C02B052SP02 Release 1.2.52.2  Apr 25 2014 07:27:05dddd?L
  mod = eregmatch(pattern: "Huawei (TE[0-9]0)", string: banner);
  if (!isnull(mod[1])) {
    model = mod[1];
    cpe_model = tolower(model);
    set_kb_item(name: "huawei_te/model", value: model);
  }

  vers = eregmatch(pattern: " (V[^ ]+)", string: banner);
  if (!isnull(vers[1]))
    version = vers[1];

  rel = eregmatch(pattern: "Release ([0-9.]+)", string: banner);
  if (!isnull(rel[1])) {
    set_kb_item(name: "huawei_te/release", value: rel[1]);
    extra = "Release:   " + rel[1];
  }

  set_kb_item(name: "huawei_te/detected", value: TRUE);
  set_kb_item(name: "huawei/data_communication_product/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^(V[0-9A-Z]+)", base: "cpe:/h:huawei:" + cpe_model + ":");
  if (!cpe)
    cpe = "cpe:/h:huawei:" + cpe_model;

  register_product(cpe: cpe, location: port + "/tcp", port: port, service: "telnet");

  log_message(data: build_detection_report(app: "Huawei " + model, version: version, install: port + "/tcp",
                                           cpe: cpe, concluded: vers[0], extra: extra),
              port: port);
}

exit(0);
