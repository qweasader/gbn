# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66583");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-3555");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Fedora Core 12 FEDORA-2009-13250 (proftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC12");
  script_tag(name:"insight", value:"For details, please visit the referenced advisories.

ChangeLog:

  * Thu Dec 10 2009 Paul Howarth  1.3.2c-1

  - Update to 1.3.2c, addressing the following issues:

  - SSL/TLS renegotiation vulnerability (CVE-2009-3555, bug 3324)

  - Failed database transaction can cause mod_quotatab to loop (bug 3228)

  - Segfault in mod_wrap (bug 3332)

  - sections can have  problems (bug 3337)

  - mod_wrap2 segfaults when a valid user retries the USER command (bug 3341)

  - mod_auth_file handles 'getgroups' request incorrectly (bug 3347)

  - Segfault caused by scrubbing zero-length portion of memory (bug 3350)

  - Drop upstreamed segfault patch

  * Thu Dec 10 2009 Paul Howarth  1.3.2b-3

  - Add patch for upstream bug 3350 - segfault on auth failures

  * Wed Dec  9 2009 Paul Howarth  1.3.2b-2

  - Reduce the mod_facts patch to the single commit addressing the issue with
directory names with glob characters (#521634), avoiding introducing a
further problem with  (#544002)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update proftpd' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13250");
  script_tag(name:"summary", value:"The remote host is missing an update to proftpd
announced via advisory FEDORA-2009-13250.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=533125");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.2c~1.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-ldap", rpm:"proftpd-ldap~1.3.2c~1.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mysql", rpm:"proftpd-mysql~1.3.2c~1.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-postgresql", rpm:"proftpd-postgresql~1.3.2c~1.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-debuginfo", rpm:"proftpd-debuginfo~1.3.2c~1.fc12", rls:"FC12")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
