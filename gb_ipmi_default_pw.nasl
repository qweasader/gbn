# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105923");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-10-29 11:12:02 +0700 (Wed, 29 Oct 2014)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("IPMI Default Password Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_ipmi_detect.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);

  script_tag(name:"summary", value:"It was possible to find default password/username combinations
  for the IPMI protocol.");

  script_tag(name:"vuldetect", value:"Tries to get a RAKP Message 2 (IPMI v2.0) to check the
  password hash or activate a session (IPMI v1.5).");

  script_tag(name:"insight", value:"Many IPMI enabled devices have set default username/password
  combinations. If these are not changed or disabled if opens up an easy exploitable vulnerability.");

  script_tag(name:"impact", value:"An attacker can log into the IPMI enabled device often with
  privileged permissions and gain access to the host operating system.");

  script_tag(name:"solution", value:"Change the default passwords or disable the default accounts
  if possible. Filter traffic to UDP port 623.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/105730/Supermicro-IPMI-Default-Accounts.html");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ipmi_func.inc");

debug = FALSE;

function verify_sha1_hash(password, salt, sha1) {
  local_var password, salt, sha1;
  local_var hmac;

  hmac = HMAC_SHA1(data:salt, key:password);
  return (hmac == sha1);
}

function create_rakp_salt(sid, bmcsid, randid, bmcrandid, bmcguid, username) {
  local_var sid, bmcsid, randid, bmcrandid, bmcguid, username;
  local_var salt;

  salt = raw_string(mkdword(sid), mkdword(bmcsid), randid, bmcrandid, bmcguid, 0x14, strlen(username), username);
  return salt;
}

function checksum(data) {
  local_var data;
  local_var checksum, i;

  checksum = 0;
  for (i=0; i<strlen(data); i++) {
     checksum = (checksum + ord(data[i])) % 256;
  }
  return 0x100 - checksum;
}

function createHash(alg, password, sessionid, data, seqnr) {
  local_var alg, password, sessionid, data, seqnr;

  if (alg == "MD5") {
    return MD5(password + sessionid + data + seqnr + password);
  } else {
    return password;
  }
}

port = 623;
if (!get_udp_port_state(port))
  exit(0);

usernames = make_list("", "ADMIN", "admin", "root", "USERID", "Administrator");
passwords = make_list("admin", "calvin", "PASSW0RD", "ADMIN", "changeme", "password", "superuser");

if (!soc = open_sock_udp(port))
  exit(0);

# IPMI v2.0
if (get_kb_item("ipmi/" + port + "/version/2.0")) {
  foreach username (usernames) {
    # Open Session Request
    console_session_id = rand();

    open_req = ipmi_v2_create_open_session_request(console_session_id: console_session_id, debug: debug);
    if (isnull(open_req))
      continue;

    send(socket: soc, data: open_req);
    recv = recv(socket:soc, length:1024);

    # Error Checking
    if (!recv || hexstr(recv) !~ "0600ff070611") {
      exit(0);                          # Not the right response, so exit
    }

    if (hexstr(recv[17]) == "01") {     # Try to handle "Insufficient Resources"
      sleep(3);
      continue;
    }

    bmc_session_id = ipmi_v2_parse_open_session_reply(data: recv, debug: debug);
    if (isnull(bmc_session_id))
      continue;

    console_random_id = rand_str(length:16, charset:"0123456789");

    # RAKP Message 1
    rakp_1 = ipmi_v2_create_rakp_message_1(bmc_session_id: bmc_session_id, console_id: console_random_id,
                                           username: username, debug: debug);
    if (isnull(rakp_1))
      continue;

    send(socket: soc, data: rakp_1);
    recv = recv(socket: soc, length: 1024);

    # Error Checking
    if (!recv || hexstr(recv[16]) !~ "00" || hexstr(recv[17]) !~ "00") {
      continue;
    }
    else {
      if (!infos = ipmi_v2_parse_rakp_message_reply(data: recv, debug: debug))
        continue;

      sha1_hash = infos["hash"];
      bmc_random_id = infos["rand_bmc_id"];
      bmc_guid = infos["bmc_guid"];

      foreach password (passwords) {
        salt = create_rakp_salt(sid: console_session_id, bmcsid: bmc_session_id, randid: console_random_id,
                                bmcrandid: bmc_random_id, bmcguid: bmc_guid, username: username);

        if (verify_sha1_hash(password: password, salt: salt, sha1: sha1_hash)) {
          set_kb_item(name:"ipmi/credentials", value:TRUE);
          set_kb_item(name:"ipmi/" + port + "/credentials", value:username + "/" + password);
          if (username == "") {
            username = "<blank>";
          }
          report += username + "/" + password + "\n";
          break;
        }
      }
    }
  }
}
# IPMI v1.5
else {
  # Channel Capabilities
  getChannelAuthCap = raw_string(0x06, 0x00, 0xff, 0x07,        # RMCP
                                 0x00,                          # Auth Type = NONE
                                 0x00, 0x00, 0x00, 0x00,        # Session Seq Number
                                 0x00, 0x00, 0x00, 0x00,        # Session ID
                                 0x09,                          # Message Length
                                 # IPMI Message
                                 0x20,                          # Responder Address
                                 0x18,                          # netFn/rsLUN
                                 checksum(data:raw_string(0x20, 0x18)),
                                 0x81,                          # Requester Address
                                 0x04,                          # reqSeq, reqLUN
                                 0x38,                          # Get Channel Auth Capabilities (command)
                                 0x0e,                          # Channel Number (this channel)
                                 0x04,                          # Request Administrator level
                                 checksum(data:raw_string(0x81, 0x04, 0x38, 0x0e, 0x04))
                                );

  send(socket:soc, data:getChannelAuthCap);
  recv = recv(socket:soc, length:1024);
  if (!recv)
    exit(0);

  auth_support = dec2bin(dec:ord(recv[22]));

  if (auth_support[5] == 1) {
    authAlg = "MD5";
    authType = raw_string(0x02);
  }
  else if (auth_support[3] == 1) {
    authAlg = "PW";
    authType = raw_string(0x04);
  }
  else {
    exit(0); # No suitable authentication algorithm so just exit
  }

  foreach username (usernames) {
    # Session Challenge
    paddedUsername = username;
    while (strlen(paddedUsername) < 16) {
      paddedUsername = paddedUsername + raw_string(0x00);
    }
    foreach password (passwords) {
      getSessChallenge = raw_string(0x06, 0x00, 0xff, 0x07,     # RMCP
                                    0x00,                       # Auth Type = NONE
                                    0x00, 0x00, 0x00, 0x00,     # Session Seq Number
                                    0x00, 0x00, 0x00, 0x00,     # Session ID
                                    0x18,                       # Message Length
                                    # IPMI Message
                                    0x20,                       # Responder Address
                                    0x18,                       # netFn/rsLUN
                                    0xc8,                       # checksum
                                    0x81,                       # Requester Address
                                    0x08,                       # reqSeq, reqLUN
                                    0x39,                       # Get Session Challenge (command)
                                    authType,                   # Auth Type for Challenge
                                    paddedUsername,
                                    checksum(data:raw_string(0x81, 0x08, 0x39, authType, paddedUsername))
                                   );

      send(socket:soc, data:getSessChallenge);
      recv = recv(socket:soc, length:1024);

      # Error Checking
      if (!recv || hexstr(recv[20]) != "00") {
        break;
      }

      sessionID = substr(recv, 21, 24);
      challenge = substr(recv, 25, 40);
      sequenceNum = raw_string(0x00, 0x00, 0x00, 0x00);

      # Activate Session
      paddedPassword = password;
      while (strlen(paddedPassword) < 16) {
        paddedPassword = paddedPassword + raw_string(0x00);
      }

      chksum = checksum(data:raw_string(0x81, 0x0c, 0x3a, authType, 0x04, challenge, 0xaa, 0x9b, 0x59, 0x3a));
      data = raw_string(0x20, 0x18, 0xc8, 0x81, 0x0c, 0x3a, authType, 0x04, challenge,
                        0xaa, 0x9b, 0x59, 0x3a, chksum);
      authCode = createHash(alg:authAlg, password:paddedPassword, sessionid:sessionID,
                            data:data, seqnr:sequenceNum);

      activateSession = raw_string(0x06, 0x00, 0xff, 0x07,      # RMCP
                                   authType,                    # Auth Type
                                   0x00, 0x00, 0x00, 0x00,      # Session Seq Number
                                   sessionID,
                                   authCode,                    # AuthCode
                                   0x1d,                        # Message Length
                                   # IPMI Message
                                   0x20,                        # Responder Address
                                   0x18,                        # netFn/rsLUN
                                   0xc8,                        # checksum
                                   0x81,                        # Requester Address
                                   0x0c,                        # reqSeq/reqLUN
                                   0x3a,                        # Activate Session (command)
                                   authType,                    # Auth Type
                                   0x04,                        # Max Priv Level (Administrator level)
                                   challenge,
                                   0xaa, 0x9b, 0x59, 0x3a,      # initial outbound seq number
                                   chksum
                                  );

      send(socket:soc, data:activateSession);
      recv = recv(socket:soc, length:1024);

      # Error checking
      if (!recv) {
        continue;
      }

      if (strlen(recv) > 36 && hexstr(recv[36]) == "00") {
        set_kb_item(name:"ipmi/credentials", value:TRUE);
        set_kb_item(name:"ipmi/" + port + "/credentials", value:username + "/" + password);
        if (username == "") {
          username = "<blank>";
        }
        report += username + "/" + password + "\n";
        break;
      }
    }
  }
}

close(soc);

if (report) {
  report = string('Found the following default Username/Password combination:\n\n', report);
  security_message(port: port, proto: "udp", data: chomp(report));
}
