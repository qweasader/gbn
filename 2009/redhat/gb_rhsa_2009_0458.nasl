# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63910");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:0458");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_4");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0458.

GPdf is a viewer for Portable Document Format (PDF) files.

Multiple integer overflow flaws were found in GPdf's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause GPdf to crash
or, potentially, execute arbitrary code when opened. (CVE-2009-0147,
CVE-2009-1179)

Multiple buffer overflow flaws were found in GPdf's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause GPdf to crash
or, potentially, execute arbitrary code when opened. (CVE-2009-0146,
CVE-2009-1182)

Multiple flaws were found in GPdf's JBIG2 decoder that could lead to the
freeing of arbitrary memory. An attacker could create a malicious PDF file
that would cause GPdf to crash or, potentially, execute arbitrary code when
opened. (CVE-2009-0166, CVE-2009-1180)

Multiple input validation flaws were found in GPdf's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause GPdf to crash
or, potentially, execute arbitrary code when opened. (CVE-2009-0800)

Multiple denial of service flaws were found in GPdf's JBIG2 decoder. An
attacker could create a malicious PDF that would cause GPdf to crash when
opened. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

Red Hat would like to thank Braden Thomas and Drew Yao of the Apple Product
Security team, and Will Dormann of the CERT/CC for responsibly reporting
these flaws.

Users are advised to upgrade to this updated package, which contains
backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0458.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gpdf", rpm:"gpdf~2.8.2~7.7.2.el4_7.4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gpdf-debuginfo", rpm:"gpdf-debuginfo~2.8.2~7.7.2.el4_7.4", rls:"RHENT_4")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
