# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69021");
  script_version("2024-07-01T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:38 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 17:36:14 +0000 (Fri, 28 Jun 2024)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839", "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843", "CVE-2010-0844", "CVE-2010-0845", "CVE-2010-0846", "CVE-2010-0847", "CVE-2010-0848", "CVE-2010-0849", "CVE-2010-0850", "CVE-2010-0886", "CVE-2010-0887");
  script_name("Gentoo Security Advisory GLSA 201006-18 (sun-jre-bin sun-jdk emul-linux-x86-java)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The Oracle JDK and JRE are vulnerable to multiple unspecified
    vulnerabilities.");
  script_tag(name:"solution", value:"All Oracle JRE 1.6.x users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.6.0.20'

All Oracle JDK 1.6.x users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.6.0.20'

All users of the precompiled 32bit Oracle JRE 1.6.x should upgrade to
    the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.6.0.20'

All Oracle JRE 1.5.x, Oracle JDK 1.5.x, and precompiled 32bit Oracle
    JRE 1.5.x users are strongly advised to unmerge Java 1.5:

    # emerge --unmerge =app-emulation/emul-linux-x86-java-1.5*
    # emerge --unmerge =dev-java/sun-jre-bin-1.5*
    # emerge --unmerge =dev-java/sun-jdk-1.5*

Gentoo is ceasing support for the 1.5 generation of the Oracle Java
    Platform in accordance with upstream. All 1.5 JRE versions are masked
    and will be removed shortly. All 1.5 JDK versions are marked as
    'build-only' and will be masked for removal shortly. Users are advised
    to change their default user and system Java implementation to an
    unaffected version. For example:

    # java-config --set-system-vm sun-jdk-1.6

For more information, please consult the Gentoo Linux Java
    documentation.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201006-18");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=306579");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=314531");
  script_xref(name:"URL", value:"http://www.gentoo.org/doc/en/java.xml#doc_chap4");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/critical-patch-updates/javacpumar2010.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201006-18.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-java/sun-jre-bin", unaffected: make_list("ge 1.6.0.20"), vulnerable: make_list("lt 1.6.0.20"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-java/sun-jdk", unaffected: make_list("ge 1.6.0.20"), vulnerable: make_list("lt 1.6.0.20"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/emul-linux-x86-java", unaffected: make_list("ge 1.6.0.20"), vulnerable: make_list("lt 1.6.0.20"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
