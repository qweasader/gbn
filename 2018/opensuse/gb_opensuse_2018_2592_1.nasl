# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852047");
  script_version("2021-06-25T11:00:33+0000");
  script_cve_id("CVE-2018-12434");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-06 16:54:00 +0000 (Mon, 06 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-10-26 06:37:51 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for libressl (openSUSE-SU-2018:2592-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:2592-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libressl'
  package(s) announced via the openSUSE-SU-2018:2592-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libressl to version 2.8.0 fixes the following issues:

  Security issues fixed:

  - CVE-2018-12434: Avoid a timing side-channel leak when generating DSA and
  ECDSA signatures. (boo#1097779)

  - Reject excessively large primes in DH key generation.

  Other bugs fixed:

  - Fixed a pair of 20+ year-old bugs in X509_NAME_add_entry.

  - Tighten up checks for various X509_VERIFY_PARAM functions, 'poisoning'
  parameters so that an unverified certificate cannot be used if it fails
  verification.

  - Fixed a potential memory leak on failure in ASN1_item_digest.

  - Fixed a potential memory alignment crash in asn1_item_combine_free.

  - Removed unused SSL3_FLAGS_DELAY_CLIENT_FINISHED and
  SSL3_FLAGS_POP_BUFFER flags in write path, simplifying IO paths.

  - Removed SSL_OP_TLS_ROLLBACK_BUG buggy client workarounds.

  - Added const annotations to many existing APIs from OpenSSL, making
  interoperability easier for downstream applications.

  - Added a missing bounds check in c2i_ASN1_BIT_STRING.

  - Removed three remaining single DES cipher suites.

  - Fixed a potential leak/incorrect return value in DSA signature
  generation.

  - Added a blinding value when generating DSA and ECDSA signatures, in
  order to reduce the possibility of a side-channel attack leaking the
  private key.

  - Added ECC constant time scalar multiplication support.

  - Revised the implementation of RSASSA-PKCS1-v1_5 to match the
  specification in RFC 8017.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-950=1");

  script_tag(name:"affected", value:"libressl on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"libcrypto43", rpm:"libcrypto43~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcrypto43-debuginfo", rpm:"libcrypto43-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl", rpm:"libressl~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-debuginfo", rpm:"libressl-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-debugsource", rpm:"libressl-debugsource~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-devel", rpm:"libressl-devel~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssl45", rpm:"libssl45~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssl45-debuginfo", rpm:"libssl45-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtls17", rpm:"libtls17~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtls17-debuginfo", rpm:"libtls17-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-devel-doc", rpm:"libressl-devel-doc~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcrypto43-32bit", rpm:"libcrypto43-32bit~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcrypto43-32bit-debuginfo", rpm:"libcrypto43-32bit-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-devel-32bit", rpm:"libressl-devel-32bit~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssl45-32bit", rpm:"libssl45-32bit~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssl45-32bit-debuginfo", rpm:"libssl45-32bit-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtls17-32bit", rpm:"libtls17-32bit~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtls17-32bit-debuginfo", rpm:"libtls17-32bit-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
