# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63649");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:078 (evolution-data-server)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.0|2008\.1|2009\.0)");
  script_tag(name:"insight", value:"A wrong handling of signed Secure/Multipurpose Internet Mail Extensions
(S/MIME) e-mail messages enables attackers to spoof its signatures
by modifying the latter copy (CVE-2009-0547).

Crafted authentication challenge packets (NT Lan Manager type 2) sent
by a malicious remote mail server enables remote attackers either
to cause denial of service and to read information from the process
memory of the client (CVE-2009-0582).

Multiple integer overflows in Base64 encoding functions enables
attackers either to cause denial of service and to execute arbitrary
code (CVE-2009-0587).

This update provides fixes for those vulnerabilities.

Update:

evolution-data-server packages from Mandriva Linux distributions
2008.1 and 2009.0 are not affected by CVE-2009-0587.

Affected: 2008.0, 2008.1, 2009.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:078");
  script_tag(name:"summary", value:"The remote host is missing an update to evolution-data-server
announced via advisory MDVSA-2009:078.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcamel10", rpm:"libcamel10~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcamel-provider10", rpm:"libcamel-provider10~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libebook9", rpm:"libebook9~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecal7", rpm:"libecal7~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedata-book2", rpm:"libedata-book2~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedata-cal6", rpm:"libedata-cal6~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedataserver9", rpm:"libedataserver9~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedataserver-devel", rpm:"libedataserver-devel~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedataserverui8", rpm:"libedataserverui8~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libegroupwise13", rpm:"libegroupwise13~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libexchange-storage3", rpm:"libexchange-storage3~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64camel10", rpm:"lib64camel10~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64camel-provider10", rpm:"lib64camel-provider10~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ebook9", rpm:"lib64ebook9~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecal7", rpm:"lib64ecal7~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edata-book2", rpm:"lib64edata-book2~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edata-cal6", rpm:"lib64edata-cal6~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edataserver9", rpm:"lib64edataserver9~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edataserver-devel", rpm:"lib64edataserver-devel~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edataserverui8", rpm:"lib64edataserverui8~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64egroupwise13", rpm:"lib64egroupwise13~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64exchange-storage3", rpm:"lib64exchange-storage3~1.12.2~1.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcamel11", rpm:"libcamel11~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcamel-provider11", rpm:"libcamel-provider11~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libebook9", rpm:"libebook9~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecal7", rpm:"libecal7~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedata-book2", rpm:"libedata-book2~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedata-cal6", rpm:"libedata-cal6~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedataserver9", rpm:"libedataserver9~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedataserver-devel", rpm:"libedataserver-devel~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedataserverui8", rpm:"libedataserverui8~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libegroupwise13", rpm:"libegroupwise13~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libexchange-storage3", rpm:"libexchange-storage3~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgdata1", rpm:"libgdata1~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64camel11", rpm:"lib64camel11~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64camel-provider11", rpm:"lib64camel-provider11~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ebook9", rpm:"lib64ebook9~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecal7", rpm:"lib64ecal7~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edata-book2", rpm:"lib64edata-book2~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edata-cal6", rpm:"lib64edata-cal6~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edataserver9", rpm:"lib64edataserver9~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edataserver-devel", rpm:"lib64edataserver-devel~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edataserverui8", rpm:"lib64edataserverui8~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64egroupwise13", rpm:"lib64egroupwise13~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64exchange-storage3", rpm:"lib64exchange-storage3~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gdata1", rpm:"lib64gdata1~2.22.3~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcamel14", rpm:"libcamel14~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libebackend0", rpm:"libebackend0~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libebook9", rpm:"libebook9~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecal7", rpm:"libecal7~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedata-book2", rpm:"libedata-book2~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedata-cal6", rpm:"libedata-cal6~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedataserver11", rpm:"libedataserver11~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedataserver-devel", rpm:"libedataserver-devel~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libedataserverui8", rpm:"libedataserverui8~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libegroupwise13", rpm:"libegroupwise13~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libexchange-storage3", rpm:"libexchange-storage3~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgdata1", rpm:"libgdata1~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64camel14", rpm:"lib64camel14~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ebackend0", rpm:"lib64ebackend0~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ebook9", rpm:"lib64ebook9~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecal7", rpm:"lib64ecal7~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edata-book2", rpm:"lib64edata-book2~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edata-cal6", rpm:"lib64edata-cal6~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edataserver11", rpm:"lib64edataserver11~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edataserver-devel", rpm:"lib64edataserver-devel~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64edataserverui8", rpm:"lib64edataserverui8~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64egroupwise13", rpm:"lib64egroupwise13~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64exchange-storage3", rpm:"lib64exchange-storage3~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gdata1", rpm:"lib64gdata1~2.24.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
