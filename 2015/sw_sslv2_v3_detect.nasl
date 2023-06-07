# Copyright (C) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111012");
  script_version("2021-10-15T12:51:02+0000");
  script_cve_id("CVE-2016-0800", "CVE-2014-3566");
  script_tag(name:"last_modification", value:"2021-10-15 12:51:02 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-04-08 07:00:00 +0200 (Wed, 08 Apr 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-30 21:31:00 +0000 (Fri, 30 Nov 2018)");
  script_name("SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("SSL and TLS");
  script_dependencies("gb_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"It was possible to detect the usage of the deprecated SSLv2
  and/or SSLv3 protocol on this system.");

  script_tag(name:"vuldetect", value:"Check the used SSL protocols of the services provided by this
  system.");

  script_tag(name:"insight", value:"The SSLv2 and SSLv3 protocols contain known cryptographic
  flaws like:

  - CVE-2014-3566: Padding Oracle On Downgraded Legacy Encryption (POODLE)

  - CVE-2016-0800: Decrypting RSA with Obsolete and Weakened eNcryption (DROWN)");

  script_tag(name:"impact", value:"An attacker might be able to use the known cryptographic flaws to
  eavesdrop the connection between clients and the service to get access to sensitive data
  transferred within the secured connection.

  Furthermore newly uncovered vulnerabilities in this protocols won't receive security updates
  anymore.");

  script_tag(name:"affected", value:"All services providing an encrypted communication using the
  SSLv2 and/or SSLv3 protocols.");

  script_tag(name:"solution", value:"It is recommended to disable the deprecated SSLv2 and/or SSLv3
  protocols in favor of the TLSv1.2+ protocols. Please see the references for more information.");

  script_xref(name:"URL", value:"https://ssl-config.mozilla.org/");
  script_xref(name:"URL", value:"https://bettercrypto.org/");
  script_xref(name:"URL", value:"https://drownattack.com/");
  script_xref(name:"URL", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_xref(name:"URL", value:"https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ssl_funcs.inc");

tlsReport = "In addition to TLSv1.0+ the service is also providing the deprecated";
sslReport = "The service is only providing the deprecated";
cipherReport = "and supports one or more ciphers." +
" Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.";

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! ssvs = get_kb_item( "tls/supported/" + port ) )
  exit( 0 );

if( "SSLv2" >< ssvs ) sslv2 = TRUE;
if( "SSLv3" >< ssvs ) sslv3 = TRUE;
if( "TLSv1.0" >< ssvs ) tlsv10 = TRUE;
if( "TLSv1.1" >< ssvs ) tlsv11 = TRUE;
if( "TLSv1.2" >< ssvs ) tlsv12 = TRUE;

if( ! tlsv10 && ! tlsv11 && ! tlsv12 ) {
  if( sslv2 && sslv3 ) {
    security_message( port:port, data:sslReport + " SSLv2 and SSLv3 protocols " + cipherReport );
    exit( 0 );
  } else if( ! sslv2 && sslv3 ) {
    security_message( port:port, data:sslReport + " SSLv3 protocol " + cipherReport );
    exit( 0 );
  } else if( sslv2 && ! sslv3 ) {
    security_message( port:port, data:sslReport + " SSLv2 protocol " + cipherReport );
    exit( 0 );
  }
} else {
  if( sslv2 && sslv3 ) {
    security_message( port:port, data:tlsReport + " SSLv2 and SSLv3 protocols " + cipherReport );
    exit( 0 );
  } else if( ! sslv2 && sslv3 ) {
    security_message( port:port, data:tlsReport + " SSLv3 protocol " + cipherReport );
    exit( 0 );
  } else if( sslv2 && ! sslv3 ) {
    security_message( port:port, data:tlsReport + " SSLv2 protocol " + cipherReport );
    exit( 0 );
  }
}

exit( 99 );