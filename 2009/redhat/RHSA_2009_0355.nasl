# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63581");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:0355");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_4");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0355.

Evolution is the integrated collection of e-mail, calendaring, contact
management, communications, and personal information management (PIM) tools
for the GNOME desktop environment.

Evolution Data Server provides a unified back-end for applications which
interact with contacts, task and calendar information. Evolution Data
Server was originally developed as a back-end for Evolution, but is now
used by multiple other applications.

Evolution did not properly check the Secure/Multipurpose Internet Mail
Extensions (S/MIME) signatures used for public key encryption and signing
of e-mail messages. An attacker could use this flaw to spoof a signature by
modifying the text of the e-mail message displayed to the user. (CVE-2009-0547)

It was discovered that evolution did not properly validate NTLM (NT LAN
Manager) authentication challenge packets. A malicious server using NTLM
authentication could cause evolution to disclose portions of its memory or
crash during user authentication. (CVE-2009-0582)

Multiple integer overflow flaws which could cause heap-based buffer
overflows were found in the Base64 encoding routines used by evolution and
evolution-data-server. This could cause evolution, or an application using
evolution-data-server, to crash, or, possibly, execute an arbitrary code
when large untrusted data blocks were Base64-encoded. (CVE-2009-0587)

All users of evolution and evolution-data-server are advised to upgrade to
these updated packages, which contain backported patches to correct these
issues. All running instances of evolution and evolution-data-server must
be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0355.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.0.2~41.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~1.0.2~14.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server-debuginfo", rpm:"evolution-data-server-debuginfo~1.0.2~14.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server-devel", rpm:"evolution-data-server-devel~1.0.2~14.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-debuginfo", rpm:"evolution-debuginfo~2.0.2~41.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.0.2~41.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
