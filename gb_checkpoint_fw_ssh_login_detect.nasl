# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140454");
  script_version("2024-05-31T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-05-31 05:05:30 +0000 (Fri, 31 May 2024)");
  script_tag(name:"creation_date", value:"2017-10-26 10:52:10 +0700 (Thu, 26 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Check Point Firewall Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/checkpoint/fw/detected");

  script_tag(name:"summary", value:"SSH login based detection of Check Point Firewall.");

  exit(0);
}

include("host_details.inc");

port = get_kb_item("ssh/login/checkpoint/fw/port");

if (!show_vers = get_kb_item("ssh/login/checkpoint/fw/" + port + "/show_vers"))
  exit(0);

version = "unknown";
build = "unknown";

set_kb_item(name: "checkpoint/firewall/detected", value: TRUE);
set_kb_item(name: "checkpoint/firewall/ssh-login/detected", value: TRUE);
set_kb_item(name: "checkpoint/firewall/ssh-login/port", value: port);
set_kb_item(name: "checkpoint/firewall/ssh-login/" + port + "/concluded", value: show_vers);

# Product version Check Point Gaia R81.10
# OS build 335
# OS kernel version 3.10.0-957.21.3cpx86_64
# OS edition 64-bit
vers = eregmatch(pattern: "Check Point Gaia (R[0-9.]+)", string: show_vers);
if (!isnull(vers[1]))
  version = vers[1];

bld = eregmatch(pattern: "OS build ([0-9]+)", string: show_vers);
if (!isnull(bld[1]))
  build = bld[1];

set_kb_item(name: "checkpoint/firewall/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "checkpoint/firewall/ssh-login/" + port + "/build", value: build);

exit(0);
