# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63598");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2009-0547", "CVE-2009-0582");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_name("Fedora Core 9 FEDORA-2009-2792 (evolution-data-server)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

This update fixes two security issues:

Evolution Data Server did not properly
check the Secure/Multipurpose Internet Mail Extensions (S/MIME) signatures used
for public key encryption and signing of e-mail messages. An attacker could use
this flaw to spoof a signature by modifying the text of the e-mail message
displayed to the user. (CVE-2009-0547)

It was discovered that Evolution Data
Server did not properly validate NTLM (NT LAN Manager) authentication challenge
packets. A malicious server using NTLM authentication could cause an application
using Evolution Data Server to disclose portions of its memory or crash during
user authentication. (CVE-2009-0582)

ChangeLog:

  * Tue Mar 17 2009 Matthew Barnes  - 2.22.3-3.fc9

  - Add patch for RH bug #484925 (CVE-2009-0547, S/MIME signatures).

  - Add patch for RH bug #487685 (CVE-2009-0582, NTLM authentication).");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update evolution-data-server' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2792");
  script_tag(name:"summary", value:"The remote host is missing an update to evolution-data-server
announced via advisory FEDORA-2009-2792.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484925");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=487685");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~2.22.3~3.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~devel~2.22.3", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~doc~2.22.3", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~debuginfo~2.22.3", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
