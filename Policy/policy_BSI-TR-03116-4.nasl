# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.96176");
  script_version("2021-01-26T10:23:02+0000");
  script_tag(name:"last_modification", value:"2021-01-26 10:23:02 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"creation_date", value:"2016-02-18 11:22:31 +0100 (Thu, 18 Feb 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BSI-TR-03116-4 Policy");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_tls_version_get.nasl", "secpod_ssl_ciphers.nasl", "compliance_tests.nasl");
  script_mandatory_keys("ssl_tls/port", "secpod_ssl_ciphers/supported_ciphers");

  script_add_preference(name:"Perform check:", type:"checkbox", value:"no", id:1);

  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/BSI-TR-03116-4.pdf");

  script_tag(name:"summary", value:"The German Federal Office for Information Security published
a guideline with specifications for the use of communication methods.

This script checks the specifications for securing communication using TLS by testing if at least
one of the mandatory cipher suites are enabled on the target:

  - TLS 1.2: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

  - TLS 1.3: TLS_AES_128_GCM_SHA256");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("policy_functions.inc");

title = "BSI TR-03116-4 (mandatory cipher suites)";
solution = "Add correct ciphers";
test_type = "TLS / SSL Handshake";
test = "Perform handshake";

pf = script_get_preference("Perform check:", id:1);
if(tolower(pf) != "yes")
  exit(0);

set_kb_item(name:"policy/BSI-TR-03116-4/started", value:TRUE);

if(!port = tls_ssl_get_port()){
  value = "Error";
  compliant = "incomplete";
  comment = "No TLS / SSL port found.";
}else if(!supported_versions = get_kb_list("tls_version_get/" + port + "/version")){
  comment = "No TLS / SSL version detected.";
  value = "Error";
  compliant = "incomplete";
}else if(!ciphers = get_kb_list("secpod_ssl_ciphers/*/" + port + "/supported_ciphers")){
  value = "Error";
  compliant = "incomplete";
  comment = "No supported ciphers detected.";
}else{
  check_ciphers = make_list();

  if("TLSv1.2" >< supported_versions){
    default = ", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ";
    default += "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    check_ciphers = make_list(check_ciphers, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                              "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                              "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                              "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
  }

  if("TLSv1.3" >< supported_versions) {
    default += ", TLS_AES_128_GCM_SHA256";
    check_ciphers = make_list( check_ciphers, "TLS_AES_128_GCM_SHA256" );
  }

  if(default)
    default = str_replace(string:default, find:", ", replace:"", count:1);
  else
    default = "";

  foreach check_cipher(check_ciphers){
    if(in_array( search:check_cipher, array:ciphers)){
      ok_ciph += check_cipher + '\n';
      value += ", " + check_cipher;
    }
  }

  if(ok_ciph){
    set_kb_item(name:"policy/BSI-TR-03116-4/" + port + "/ok", value:ok_ciph);
    set_kb_item(name:"policy/BSI-TR-03116-4/ok", value:TRUE);

    value = str_replace(string:value, find:", ", replace:"", count:1);
    compliant = "yes";
    comment = "Port: " + port;

  }else{
    report = "Keiner der unter Punkt 2.2.1.2 geforderten Ciphers wurde auf dem System unter Port " + port + " gefunden.";
    set_kb_item(name:"policy/BSI-TR-03116-4/" + port + "/fail", value:report);
    set_kb_item(name:"policy/BSI-TR-03116-4/fail", value:TRUE);

    value = "None";
    compliant = "no";
    comment = "Port: " + port + ": None of the found ciphers matches the requirement";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:test, info:comment);
policy_set_kbs(type:test_type, cmd:test, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
