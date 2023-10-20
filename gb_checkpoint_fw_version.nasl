# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140454");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-26 10:52:10 +0700 (Thu, 26 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Check Point Firewall Version Detection");

  script_tag(name:"summary", value:"This Script consolidate the via SSH/HTTP detected version of the Check Point
Firewall.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl", "gb_checkpoint_fw_web_detect.nasl");
  script_mandatory_keys("checkpoint_fw/detected");

  script_xref(name:"URL", value:"https://www.checkpoint.com/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

source = "ssh";

if (!version = get_kb_item("checkpoint_fw/" + source + "/version")) {
  source = "http";
  if (!version = get_kb_item("checkpoint_fw/" + source + "/version"))
    exit(0);
  else {
    os_register_and_report(os: "Check Point Gaia", cpe: "cpe:/o:checkpoint:gaia_os", banner_type: toupper(source),
                           desc: "Check Point Firewall Version Detection", runs_key: "unixoide");
  }
}

set_kb_item(name: "checkpoint_fw/version", value: version);
set_kb_item(name: "checkpoint_fw/version_source", value: source);

cpe = 'cpe:/o:checkpoint:gaia_os:' + tolower(version);

register_product(cpe: cpe, location: source);

exit(0);
