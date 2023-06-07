# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811655");
  script_version("2022-12-15T10:11:09+0000");
  script_tag(name:"last_modification", value:"2022-12-15 10:11:09 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"creation_date", value:"2017-09-08 12:12:54 +0530 (Fri, 08 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Technicolor TC7200 Modem/Router Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of a Technicolor TC7200 Modem/Router.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

port = snmp_get_port(default:161);

if(!sysdesc = snmp_get_sysdescr(port:port))
  exit(0);

if("VENDOR: Technicolor" >< sysdesc && "TC7200" >< sysdesc) {

  model = "unknown";
  version = "unknown";
  cpe_version = "unknown";
  install = port + "/udp";

  # MODEL: TC7200.TH2v2
  # MODEL: TC7200.d1I
  # MODEL: TC7200.U
  mod = eregmatch(pattern:"MODEL: ([0-9A-Z]+).", string:sysdesc);
  if(!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name:"technicolor/model/version", value:model);
  }

  # SW_REV: SC05.00.22;
  # SW_REV: STDD.01.04;
  #
  # nb: Unclear what version this is so that one is excluded for now:
  # SW_REV: TC7200.d1IE-N23E-c7000r5712-170406-HAT
  firmvers = eregmatch(pattern:"SW_REV: ([0-9A-Z.]+);", string:sysdesc);
  if(!isnull(firmvers[1])) {
    version = firmvers[1];
    cpe_version = tolower(version);
    set_kb_item(name:"technicolor/firmware/version", value:version);
  }

  set_kb_item(name:"technicolor/tc7200/detected", value:TRUE);
  set_kb_item(name:"technicolor/tc7200/snmp/detected", value:TRUE);

  oscpe = build_cpe(value:cpe_version, exp:"^([0-9a-z.]+)", base:"cpe:/o:technicolor:tc7200_firmware:");
  if(!oscpe)
    oscpe = "cpe:/o:technicolor:tc7200_firmware";

  hwcpe = "cpe:/h:technicolor:tc7200";
  register_product(cpe:hwcpe, port:port, location:install, service:"snmp", proto:"udp");
  register_product(cpe:oscpe, port:port, location:install, service:"snmp", proto:"udp");

  os_register_and_report(os:"Technicolor TC7200 Firmware", cpe:oscpe, banner_type:"SNMP sysDescr OID",
                         port:port, proto:"udp", banner:sysdesc, desc:"Technicolor TC7200 Modem/Router Detection (SNMP)",
                         runs_key:"unixoide");

  report = build_detection_report(app:"Technicolor TC7200 Firmware", version:version, install:port + "/udp",
                                  cpe:oscpe);
  report += '\n\n';
  report += build_detection_report(app:"Technicolor TC7200", skip_version:TRUE, install:port + "/udp",
                                   cpe:hwcpe);
  report += '\n\n';
  report += 'Concluded from SNMP sysDescr OID:\n' + sysdesc;

  log_message(port:port, proto:"udp", data:report);
}

exit(0);
