# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.123056");
  script_cve_id("CVE-2014-3613", "CVE-2014-3707", "CVE-2014-8150", "CVE-2015-3143", "CVE-2015-3148");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:47 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:27:53+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:27:53 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-1254)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1254");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1254.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the ELSA-2015-1254 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[7.19.7-46]
- require credentials to match for NTLM re-use (CVE-2015-3143)
- close Negotiate connections when done (CVE-2015-3148)

[7.19.7-45]
- reject CRLFs in URLs passed to proxy (CVE-2014-8150)

[7.19.7-44]
- use only full matches for hosts used as IP address in cookies (CVE-2014-3613)
- fix handling of CURLOPT_COPYPOSTFIELDS in curl_easy_duphandle (CVE-2014-3707)

[7.19.7-43]
- fix manpage typos found using aspell (#1011101)
- fix comments about loading CA certs with NSS in man pages (#1011083)
- fix handling of DNS cache timeout while a transfer is in progress (#835898)
- eliminate unnecessary inotify events on upload via file protocol (#883002)
- use correct socket type in the examples (#997185)
- do not crash if MD5 fingerprint is not provided by libssh2 (#1008178)
- fix SIGSEGV of curl --retry when network is down (#1009455)
- allow to use TLS 1.1 and TLS 1.2 (#1012136)
- docs: update the links to cipher-suites supported by NSS (#1104160)
- allow to use ECC ciphers if NSS implements them (#1058767)
- make curl --trace-time print correct time (#1120196)
- let tool call PR_Cleanup() on exit if NSPR is used (#1146528)
- ignore CURLOPT_FORBID_REUSE during NTLM HTTP auth (#1154747)
- allow to enable/disable new AES cipher-suites (#1156422)
- include response headers added by proxy in CURLINFO_HEADER_SIZE (#1161163)
- disable libcurl-level downgrade to SSLv3 (#1154059)

[7.19.7-42]
- do not force connection close after failed HEAD request (#1168137)
- fix occasional SIGSEGV during SSL handshake (#1168668)

[7.19.7-41]
- fix a connection failure when FTPS handle is reused (#1154663)");

  script_tag(name:"affected", value:"'curl' package(s) on Oracle Linux 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.19.7~46.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.19.7~46.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.19.7~46.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
