# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66299");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
  script_cve_id("CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3886");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200911-02 (sun-jre-bin sun-jdk emul-linux-x86-java blackdown-jre blackdown-jdk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in the Sun JDK and JRE allow for several attacks,
    including the remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All Sun JRE 1.5.x users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.5.0.22'

All Sun JRE 1.6.x users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.6.0.17'

All Sun JDK 1.5.x users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.5.0.22'

All Sun JDK 1.6.x users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.6.0.17'

All users of the precompiled 32bit Sun JRE 1.5.x should upgrade to the
    latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.5.0.22'

All users of the precompiled 32bit Sun JRE 1.6.x should upgrade to the
    latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.6.0.17'

All Sun JRE 1.4.x, Sun JDK 1.4.x, Blackdown JRE, Blackdown JDK and
    precompiled 32bit Sun JRE 1.4.x users are strongly advised to unmerge
    Java 1.4:

    # emerge --unmerge =app-emulation/emul-linux-x86-java-1.4*
    # emerge --unmerge =dev-java/sun-jre-bin-1.4*
    # emerge --unmerge =dev-java/sun-jdk-1.4*
    # emerge --unmerge dev-java/blackdown-jdk
    # emerge --unmerge dev-java/blackdown-jre

Gentoo is ceasing support for the 1.4 generation of the Sun Java
    Platform in accordance with upstream. All 1.4 JRE and JDK versions are
    masked and will be removed shortly.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200911-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=182824");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=231337");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=250012");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=263810");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=280409");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=291817");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200911-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-java/sun-jre-bin", unaffected: make_list("rge 1.5.0.22", "ge 1.6.0.17"), vulnerable: make_list("lt 1.6.0.17"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-java/sun-jdk", unaffected: make_list("rge 1.5.0.22", "ge 1.6.0.17"), vulnerable: make_list("lt 1.6.0.17"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-java/blackdown-jre", unaffected: make_list(), vulnerable: make_list("le 1.4.2.03-r14"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-java/blackdown-jdk", unaffected: make_list(), vulnerable: make_list("le 1.4.2.03-r16"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/emul-linux-x86-java", unaffected: make_list("rge 1.5.0.22", "ge 1.6.0.17"), vulnerable: make_list("lt 1.6.0.17"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
