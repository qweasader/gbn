# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64215");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_name("RedHat Security Advisory RHSA-2009:1108");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_3");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1108.

The Apache HTTP Server is a popular Web server. The httpd package shipped
with Red Hat Enterprise Linux 3 contains an embedded copy of the Apache
Portable Runtime (APR) utility library, a free library of C data structures
and routines, which includes interfaces to support XML parsing, LDAP
connections, database interfaces, URI parsing, and more.

An off-by-one overflow flaw was found in the way apr-util processed a
variable list of arguments. An attacker could provide a specially-crafted
string as input for the formatted output conversion routine, which could,
on big-endian platforms, potentially lead to the disclosure of sensitive
information or a denial of service (application crash). (CVE-2009-1956)

Note: The CVE-2009-1956 flaw only affects big-endian platforms, such as the
IBM S/390 and PowerPC. It does not affect users using the httpd package on
little-endian platforms, due to their different organization of byte
ordering used to represent particular data.

A denial of service flaw was found in the apr-util Extensible Markup
Language (XML) parser. A remote attacker could create a specially-crafted
XML document that would cause excessive memory consumption when processed
by the XML decoding engine. (CVE-2009-1955)

A heap-based underwrite flaw was found in the way apr-util created compiled
forms of particular search patterns. An attacker could formulate a
specially-crafted search keyword, that would overwrite arbitrary heap
memory locations when processed by the pattern preparation engine.
(CVE-2009-0023)

All httpd users should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing the updated
packages, the httpd daemon must be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1108.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.0.46~73.ent", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.0.46~73.ent", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.0.46~73.ent", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.0.46~73.ent", rls:"RHENT_3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
