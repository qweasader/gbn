# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63913");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
  script_cve_id("CVE-2009-0844", "CVE-2009-0846", "CVE-2009-0847", "CVE-2009-0845");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:098 (krb5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|3\.0|4\.0)");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in krb5:

The get_input_token function in the SPNEGO implementation in MIT
Kerberos 5 (aka krb5) 1.5 through 1.6.3 allows remote attackers to
cause a denial of service (daemon crash) and possibly obtain sensitive
information via a crafted length value that triggers a buffer over-read
(CVE-2009-0844).

The asn1_decode_generaltime function in lib/krb5/asn.1/asn1_decode.c in
the ASN.1 GeneralizedTime decoder in MIT Kerberos 5 (aka krb5) before
1.6.4 allows remote attackers to cause a denial of service (daemon
crash) or possibly execute arbitrary code via vectors involving an
invalid DER encoding that triggers a free of an uninitialized pointer
(CVE-2009-0846).

The asn1buf_imbed function in the ASN.1 decoder in MIT Kerberos 5
(aka krb5) 1.6.3, when PK-INIT is used, allows remote attackers to
cause a denial of service (application crash) via a crafted length
value that triggers an erroneous malloc call, related to incorrect
calculations with pointer arithmetic (CVE-2009-0847).

The updated packages have been patched to correct these issues.

Update:

krb5 packages for Mandriva Linux Corporate Server 3 and 4 are not
affected by CVE-2009-0844 and CVE-2009-0845

Affected: 2008.1, 2009.0, Corporate 3.0, Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:098");
  script_tag(name:"summary", value:"The remote host is missing an update to krb5
announced via advisory MDVSA-2009:098.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ftp-client-krb5", rpm:"ftp-client-krb5~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ftp-server-krb5", rpm:"ftp-server-krb5~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-client-krb5", rpm:"telnet-client-krb5~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-server-krb5", rpm:"telnet-server-krb5~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.6.3~6.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ftp-client-krb5", rpm:"ftp-client-krb5~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ftp-server-krb5", rpm:"ftp-server-krb5~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-client-krb5", rpm:"telnet-client-krb5~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-server-krb5", rpm:"telnet-server-krb5~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.6.3~6.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ftp-client-krb5", rpm:"ftp-client-krb5~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ftp-server-krb5", rpm:"ftp-server-krb5~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb51", rpm:"libkrb51~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb51-devel", rpm:"libkrb51-devel~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-client-krb5", rpm:"telnet-client-krb5~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-server-krb5", rpm:"telnet-server-krb5~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb51", rpm:"lib64krb51~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb51-devel", rpm:"lib64krb51-devel~1.3~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ftp-client-krb5", rpm:"ftp-client-krb5~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ftp-server-krb5", rpm:"ftp-server-krb5~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-client-krb5", rpm:"telnet-client-krb5~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-server-krb5", rpm:"telnet-server-krb5~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.4.3~5.7.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
