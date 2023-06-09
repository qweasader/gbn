# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902658");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2005-1794");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-03-01 13:38:23 +0530 (Thu, 01 Mar 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Microsoft RDP Server Private Key Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("ms_rdp_detect.nasl");
  script_require_ports("Services/ms-wbt-server", 3389);
  script_mandatory_keys("rdp/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/15605/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13818");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/21954");
  script_xref(name:"URL", value:"http://www.oxid.it/downloads/rdp-gbu.pdf");
  script_xref(name:"URL", value:"http://sourceforge.net/p/xrdp/mailman/message/32732056");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain
  sensitive information.");

  script_tag(name:"affected", value:"All Microsoft-compatible RDP (5.2 or earlier) software.");

  script_tag(name:"insight", value:"The flaw is due to RDP server which stores an RSA private key
  used for signing a terminal server's public key in the mstlsapi.dll library,
  which allows remote attackers to calculate a valid signature and further
  perform a man-in-the-middle (MITM) attacks to obtain sensitive information.");

  script_tag(name:"summary", value:"Remote Desktop Protocol server is prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.

  A Workaround is to connect only to terminal services over trusted networks.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");
include("port_service_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# To Reverse into little endian
function reverse_data(data)
{
  local_var val, i;

  val = NULL;

  for(i= strlen(data)-1; i>=0; i--)
    val += data[i];

  return val;
}

port = service_get_port( default:3389, proto:"ms-wbt-server" );
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string(0x03, 0x00, 0x01, 0x96, 0x02, 0xf0, 0x80, 0x7f, 0x65,
                 0x82, 0x01, 0x8a, 0x04, 0x01, 0x01, 0x04, 0x01, 0x01,
                 0x01, 0x01, 0xff, 0x30, 0x20, 0x02, 0x02, 0x00, 0x22,
                 0x02, 0x02, 0x00, 0x02, 0x02, 0x02, 0x00, 0x00, 0x02,
                 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x00, 0x02, 0x02,
                 0x00, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x02, 0x00,
                 0x02, 0x30, 0x20, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02,
                 0x00, 0x01, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00,
                 0x01, 0x02, 0x02, 0x00, 0x00, 0x02, 0x02, 0x00, 0x01,
                 0x02, 0x02, 0x04, 0x20, 0x02, 0x02, 0x00, 0x02, 0x30,
                 0x20, 0x02, 0x02, 0xff, 0xff, 0x02, 0x02, 0xfc, 0x17,
                 0x02, 0x02, 0xff, 0xff, 0x02, 0x02, 0x00, 0x01, 0x02,
                 0x02, 0x00, 0x00, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02,
                 0xff, 0xff, 0x02, 0x02, 0x00, 0x02, 0x04, 0x82, 0x01,
                 0x17, 0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01, 0x81,
                 0x0E, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00,
                 0x44, 0x75, 0x63, 0x61, 0x81, 0x00, 0x01, 0xC0, 0xD4,
                 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x04, 0x00, 0x03,
                 0x01, 0xCA, 0x03, 0xAA, 0x09, 0x04, 0x00, 0x00, 0x28,
                 0x0A, 0x00, 0x00, 0x79, 0x00, 0x70, 0x00, 0x65, 0x00,
                 0x6e, 0x00, 0x56, 0x00, 0x41, 0x00, 0x83, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x01, 0xCA, 0x01, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x04, 0xC0, 0x0C, 0x00, 0x09, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xC0, 0x0C, 0x00,
                 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                 0xC0, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x63, 0x6C,
                 0x69, 0x70, 0x72, 0x64, 0x72, 0x00, 0xC0, 0xA0, 0x00, 0x00);

# Send the MCS Req
send(socket:soc, data:req);
resp = recv(socket:soc, length:4096);
close(soc);

if(!resp || ("RSA1" >!< resp)){
  exit(0);
}

blob = strstr (resp, "RSA1");
firstStr = strlen(resp) - strlen(blob) - 16;

publickeyLen = getdword(blob:blob, pos:8) / 8;
endStr = firstStr + 0x24 + publickeyLen + 7;
if(strlen(resp) < endStr){
  exit (0);
}

publicKey = substr(resp, firstStr, endStr);

# extract the Signature
sig = substr(resp, endStr+5, strlen(resp)-9);
sig = reverse_data(data:sig);

# Public exponent e
e = raw_string(0x5B, 0x7B, 0x88, 0xC0);
e = reverse_data(data:e);

# Public Mod n
n = raw_string(0x3D, 0x3A, 0x5E, 0xBD, 0x72, 0x43, 0x3E, 0xC9, 0x4D, 0xBB,
               0xC1, 0x1E, 0x4A, 0xBA, 0x5F, 0xCB, 0x3E, 0x88, 0x20, 0x87,
               0xEF, 0xF5, 0xC1, 0xE2, 0xD7, 0xB7, 0x6B, 0x9A, 0xF2, 0x52,
               0x45, 0x95, 0xCE, 0x63, 0x65, 0x6B, 0x58, 0x3A, 0xFE, 0xEF,
               0x7C, 0xE7, 0xBF, 0xFE, 0x3D, 0xF6, 0x5C, 0x7D, 0x6C, 0x5E,
               0x06, 0x09, 0x1A, 0xF5, 0x61, 0xBB, 0x20, 0x93, 0x09, 0x5F,
               0x05, 0x6D, 0xEA, 0x87);

n = reverse_data(data:n);

# Size of both the signatures should be same
if(strlen(sig) == strlen(n))
{
  keyHash = MD5(publicKey);

  decrypted = rsa_public_decrypt(sig:sig, e:e, n:n);

  key_decrypted = reverse_data(data:decrypted);
  if(!key_decrypted){
    exit (0);
  }

  if (keyHash >< key_decrypted){
    security_message( port:port );
    exit( 0 );
  }
}

exit( 0 );
