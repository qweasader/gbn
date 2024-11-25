# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63583");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0339");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0339.

Little Color Management System (LittleCMS, or simply lcms) is a
small-footprint, speed-optimized open source color management engine.

Multiple integer overflow flaws which could lead to heap-based buffer
overflows, as well as multiple insufficient input validation flaws, were
found in LittleCMS. An attacker could use these flaws to create a
specially-crafted image file which could cause an application using
LittleCMS to crash, or, possibly, execute arbitrary code when opened by a
victim. (CVE-2009-0723, CVE-2009-0733)

A memory leak flaw was found in LittleCMS. An application using LittleCMS
could use excessive amount of memory, and possibly crash after using all
available memory, if used to open specially-crafted images. (CVE-2009-0581)

Red Hat would like to thank Chris Evans from the Google Security Team for
reporting these issues.

All users of LittleCMS should install these updated packages, which upgrade
LittleCMS to version 1.18. All running applications using the lcms library
must be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0339.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"lcms", rpm:"lcms~1.18~0.1.beta1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lcms-debuginfo", rpm:"lcms-debuginfo~1.18~0.1.beta1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-lcms", rpm:"python-lcms~1.18~0.1.beta1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lcms-devel", rpm:"lcms-devel~1.18~0.1.beta1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
