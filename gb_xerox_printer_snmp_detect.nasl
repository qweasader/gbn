# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141825");
  script_version("2022-03-18T15:21:58+0000");
  script_tag(name:"last_modification", value:"2022-03-18 15:21:58 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"creation_date", value:"2019-01-04 13:53:28 +0700 (Fri, 04 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Xerox Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Xerox printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# Some Xerox printers return a hex representative
# e.g. 58 65 72 6F 78 C2 AE 20 43 6F 6C 6F 72 20 31 30 ...
# Change back to a string and remove unprintable chars
if (sysdesc =~ "^[0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2}") {
  sysdesc = hex2str(str_replace(string: sysdesc, find: " ", replace: ""));
  sysdesc = bin2string(ddata: sysdesc, noprint_replacement: "");
}

# Xerox AltaLink C8045; SS 100.002.008.05702, ...
# FUJI XEROX DocuPrint CM305 df; ...
# nb: Keep in sync with the pattern used in dont_print_on_printers.nasl
if (sysdesc =~ "^(FUJI )?(Xerox|XEROX) ") {
  set_kb_item(name: "xerox/printer/detected", value: TRUE);
  set_kb_item(name: "xerox/printer/snmp/detected", value: TRUE);
  set_kb_item(name: "xerox/printer/snmp/port", value: port);
  set_kb_item(name: "xerox/printer/snmp/" + port + "/concluded", value: sysdesc);

  # FUJI XEROX DocuColor 1450 GA ;ESS1.102.18,IOT 72.51.0,HCF 3.33.0,FIN C18.29.0,IIT 7.10.0,ADF 21.3.0,SJFI3.0.17,SSMI1.15.2
  mod = eregmatch(pattern: "(Xerox|FUJI XEROX) ([^;]+);?", string: sysdesc);
  if (!isnull(mod[2])) {
    if (";" >!< mod[0]) {
      # Likely extracted from hex response so just take the first part
      model = split(mod[2], sep: " ", keep: FALSE);
      set_kb_item(name: "xerox/printer/snmp/" + port + "/model", value: model[0]);
    } else {
      set_kb_item(name: "xerox/printer/snmp/" + port + "/model", value: mod[2]);
    }
  }

  # Xerox AltaLink C8045; SS 100.002.008.05702, NC 100.002.05702.1057305v9, UI 100.002.05702, ME 063.022.000, CC 100.002.05702, DF 007.019.000, FI 010.019.000, FA 003.012.013, CCOS 100.008.05702, NCOS 100.008.05702, SC 013.015.006, SU 100.002.05702
  vers = eregmatch(pattern: "SS ([0-9.]+),", string: sysdesc);
  if (!isnull(vers[1])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[1]);
    exit(0);
  }


  # Xerox WorkCentre 7556 v1 Multifunction System; System Software 061.121.225.14700, ESS 061.125.14620.LL
  vers = eregmatch(pattern: "System Software ([0-9.]+),", string: sysdesc);
  if (!isnull(vers[1])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[1]);
    exit(0);
  }

  # FUJI XEROX DocuPrint CM305 df; Net 16.41,ESS 201210101131,IOT 03.00.05
  # FUJI XEROX ApeosPort-IV C3375 ;ESS1.131.3,IOT 84.14.0,ADF 7.16.0,FAX 1.1.14,BOOT 1.0.54,SJFI3.3.0,SSMI1.20.1
  vers = eregmatch(pattern: "ESS( )?([0-9.]+),", string: sysdesc);
  if (!isnull(vers[2])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[2]);
    exit(0);
  }

  # Xerox Phaser 6510; System 64.50.61, Controller 1.57.3, IOT 1.1.0, IOT2 4.11.0, Panel 1.7.0, Boot 11.1.216, RSEP 1.8.25
  # Xerox DocuColor 242 with EFI Fiery Controller; SW2.0,Controller ROM1.210.25, IOT 8.35.0, HCF 5.2.0, FIN C17.19.0, IIT 1.6.1, ADF 12.2.0, Update Info 1-S4225,1-U8E58,1-Z4E66
  vers = eregmatch(pattern: ", ?Controller (ROM)?([0-9.]+)", string: sysdesc);
  if (!isnull(vers[2])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[2]);
    exit(0);
  }

  exit(0);
} else {
  mod_oid = "1.3.6.1.2.1.25.3.2.1.3.1";
  m = snmp_get(port: port, oid: mod_oid);

  # Xerox D95 Copier-Printer v 84. 19.  0 Multifunction System
  # Xerox Color EX C60-C70 with EFI Fiery Controller;
  # Xerox D110 Copier-Printer v 84. 13.  0 Multifunction System
  # Xerox 700 Digital Color Press with EFI Fiery Controller;
  if (m =~ "^Xerox") {
    set_kb_item(name: "xerox/printer/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/snmp/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/snmp/port", value: port);
    set_kb_item(name: "xerox/printer/snmp/" + port + "/concluded", value: m + " via OID: " + mod_oid);

    mod = eregmatch(pattern: "Xerox (.+) (Copier|with|Digital)", string: m);
    if (!isnull(mod[1]))
      set_kb_item(name: "xerox/printer/snmp/" + port + "/model", value: mod[1]);
  }
}

exit(0);
