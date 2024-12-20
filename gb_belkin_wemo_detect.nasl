# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140282");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-08 11:52:33 +0700 (Tue, 08 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Belkin WeMo Device Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Belkin WeMo devices.

  The script sends a connection request to the server and attempts to detect Belkin WeMo devices and to
  extract its firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 49153);
  script_mandatory_keys("Unspecified-UPnP/banner");

  script_xref(name:"URL", value:"http://www.belkin.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 49153);

url = "/setup.xml";
req = http_get(port: port, item: url);
# Don't use http_keepalive_send_recv() here as we often don't get the whole response.
res = http_send_recv(port: port, data: req);

if ("Belkin" >< res && "<friendlyName>WeMo" >< res) {
  buf = eregmatch(pattern: "<friendlyName>WeMo (.*)</friendlyName", string: res);
  if (!isnull(buf[1])) {
    model = buf[1];
    set_kb_item(name: "belkin_wemo/model", value: model);
  }

  vers = eregmatch(pattern: "<firmwareVersion>.*_([0-9.]+)\..*</firmwareVersion>", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "belkin_wemo/version", value: version);
  }

  buf = eregmatch(pattern: "<modelDescription>([^</]+)", string: res);
  if (!isnull(buf[1]))
    extra = "Description:   " + buf[1] + "\n";

  buf = eregmatch(pattern: "<modelNumber>([^</]+)", string: res);
  if (!isnull(buf[1]))
    extra += "Model Number:  " + buf[1] + "\n";

  buf = eregmatch(pattern: "<macAddress>([^</]+)", string: res);
  if (!isnull(buf[1])) {
    extra += "Mac Address:   " + buf[1] + "\n";
    register_host_detail(name: "MAC", value: buf[1], desc: "gb_belkin_wemo_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: buf[1]);
  }

  buf = eregmatch(pattern: "<binaryState>(0|1)", string: res);
  if (!isnull(buf[1]))
    if (buf[1] == "0")
      extra += "State:        OFF";
    else
      extra += "State:        ON";

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:belkin:wemo_home_automation_firmware:");
  if (!cpe)
    cpe = 'cpe:/a:belkin:wemo_home_automation_firmware';

  set_kb_item(name: "belkin_wemo/detected", value: TRUE);

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Belkin WeMo " + model, version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: url, extra: extra),
              port: port);
  exit(0);
}

exit(0);
