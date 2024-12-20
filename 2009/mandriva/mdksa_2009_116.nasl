# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64129");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2009-1415", "CVE-2009-1416", "CVE-2009-1417");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:116 (gnutls)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|4\.0)");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in gnutls:

lib/pk-libgcrypt.c in libgnutls in GnuTLS before 2.6.6 does not
properly handle invalid DSA signatures, which allows remote attackers
to cause a denial of service (application crash) and possibly have
unspecified other impact via a malformed DSA key that triggers a (1)
free of an uninitialized pointer or (2) double free (CVE-2009-1415).

lib/gnutls_pk.c in libgnutls in GnuTLS 2.5.0 through 2.6.5 generates
RSA keys stored in DSA structures, instead of the intended DSA keys,
which might allow remote attackers to spoof signatures on certificates
or have unspecified other impact by leveraging an invalid DSA key
(CVE-2009-1416).

gnutls-cli in GnuTLS before 2.6.6 does not verify the activation
and expiration times of X.509 certificates, which allows remote
attackers to successfully present a certificate that is (1) not yet
valid or (2) no longer valid, related to lack of time checks in the
_gnutls_x509_verify_certificate function in lib/x509/verify.c in
libgnutls_x509, as used by (a) Exim, (b) OpenLDAP, and (c) libsoup
(CVE-2009-1417).

The updated packages have been patched to prevent this.

Affected: 2008.1, 2009.0, 2009.1, Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:116");
  script_tag(name:"summary", value:"The remote host is missing an update to gnutls
announced via advisory MDVSA-2009:116.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.3.0~2.5mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls26", rpm:"libgnutls26~2.3.0~2.5mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~2.3.0~2.5mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls26", rpm:"lib64gnutls26~2.3.0~2.5mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls-devel", rpm:"lib64gnutls-devel~2.3.0~2.5mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.4.1~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls26", rpm:"libgnutls26~2.4.1~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~2.4.1~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls26", rpm:"lib64gnutls26~2.4.1~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls-devel", rpm:"lib64gnutls-devel~2.4.1~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.6.4~1.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls26", rpm:"libgnutls26~2.6.4~1.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~2.6.4~1.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls26", rpm:"lib64gnutls26~2.6.4~1.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls-devel", rpm:"lib64gnutls-devel~2.6.4~1.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~1.0.25~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls11", rpm:"libgnutls11~1.0.25~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls11-devel", rpm:"libgnutls11-devel~1.0.25~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls11", rpm:"lib64gnutls11~1.0.25~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls11-devel", rpm:"lib64gnutls11-devel~1.0.25~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
