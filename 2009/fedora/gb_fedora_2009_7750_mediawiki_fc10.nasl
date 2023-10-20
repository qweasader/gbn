# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64409");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2008-5249", "CVE-2008-5250", "CVE-2008-5252", "CVE-2008-5687", "CVE-2008-5688");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-7750 (mediawiki)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

This update upgrades mediawiki code to 1.15.1 and fixes some path references.
Upstream comments:  This is a security and bugfix release of MediaWiki 1.15.1
and 1.14.1.    A cross-site scripting (XSS) vulnerability was discovered. Only
versions 1.14.0, 1.15.0 and release candidates for those releases are affected.

ChangeLog:

  * Mon Jul 13 2009 Axel Thimm  - 1.15.1-48

  - Update to 1.15.1 (Fixes XSS vulnerability).

  * Sat Jul 11 2009 Axel Thimm  - 1.15.0-47

  - Fix api.php breakage.

  * Sat Jun 13 2009 Axel Thimm  - 1.15.0-46

  - Update to 1.15.0.

  * Thu Apr 16 2009 S390x secondary arch maintainer

  - ExcludeArch sparc64, s390, s390x as we don't have OCaml on those archs
(added sparc64 per request from the sparc maintainer)

  * Sat Feb 28 2009 Axel Thimm  - 1.14.0-45

  - Update to 1.14.0.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update mediawiki' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7750");
  script_tag(name:"summary", value:"The remote host is missing an update to mediawiki
announced via advisory FEDORA-2009-7750.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484855");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=494362");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=494880");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.15.1~48.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mediawiki-math", rpm:"mediawiki-math~1.15.1~48.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mediawiki-nomath", rpm:"mediawiki-nomath~1.15.1~48.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mediawiki-debuginfo", rpm:"mediawiki-debuginfo~1.15.1~48.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
