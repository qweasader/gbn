# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64597");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2409");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 17:21:52 +0000 (Wed, 14 Feb 2024)");
  script_name("RedHat Security Advisory RHSA-2009:1207");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates to Netscape Portable Runtime (NSPR)
and Network Security Services (NSS) announced in advisory RHSA-2009:1207.

These updated packages upgrade NSS from the previous version, 3.12.2, to a
prerelease of version 3.12.4. The version of NSPR has also been upgraded
from 4.7.3 to 4.7.4.

Moxie Marlinspike reported a heap overflow flaw in a regular expression
parser in the NSS library used by browsers such as Mozilla Firefox to match
common names in certificates. A malicious website could present a
carefully-crafted certificate in such a way as to trigger the heap
overflow, leading to a crash or, possibly, arbitrary code execution with
the permissions of the user running the browser. (CVE-2009-2404)

Note: in order to exploit this issue without further user interaction in
Firefox, the carefully-crafted certificate would need to be signed by a
Certificate Authority trusted by Firefox, otherwise Firefox presents the
victim with a warning that the certificate is untrusted. Only if the user
then accepts the certificate will the overflow take place.

Dan Kaminsky discovered flaws in the way browsers such as Firefox handle
NULL characters in a certificate. If an attacker is able to get a
carefully-crafted certificate signed by a Certificate Authority trusted by
Firefox, the attacker could use the certificate during a man-in-the-middle
attack and potentially confuse Firefox into accepting it by mistake.
(CVE-2009-2408)

Dan Kaminsky found that browsers still accept certificates with MD2 hash
signatures, even though MD2 is no longer considered a cryptographically
strong algorithm. This could make it easier for an attacker to create a
malicious certificate that would be treated as trusted by a browser. NSS
now disables the use of MD2 and MD4 algorithms inside signatures by
default. (CVE-2009-2409)

All users of nspr and nss are advised to upgrade to these updated packages,
which resolve these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1207.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.7.4~1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.7.4~1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.7.4~1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.12.3.99.3~1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.12.3.99.3~1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.12.3.99.3~1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.12.3.99.3~1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.12.3.99.3~1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
