# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63214");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_cve_id("CVE-2008-5077");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-0543 (tqsllib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

The TrustedQSL library incorrectly checked the result after  calling the
EVP_VerifyFinal function, allowing a malformed signature to be treated as a good
signature rather than as an error. Package includes a patch to fix
EVP_VerifyFinal result check.

ChangeLog:

  * Mon Jan 12 2009 Lucian Langa  - 2.0-5

  - modify patch0 to include fix for #479650 (CVE-2008-5077 related)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update tqsllib' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0543");
  script_tag(name:"summary", value:"The remote host is missing an update to tqsllib
announced via advisory FEDORA-2009-0543.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479650");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"tqsllib", rpm:"tqsllib~2.0~5.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tqsllib-devel", rpm:"tqsllib-devel~2.0~5.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tqsllib-debuginfo", rpm:"tqsllib-debuginfo~2.0~5.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
