# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64454");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2008-1679", "CVE-2008-1721", "CVE-2008-1887", "CVE-2008-2315", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144", "CVE-2008-4864", "CVE-2008-5031");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1177");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_4");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1177.

Python is an interpreted, interactive, object-oriented programming
language.

When the assert() system call was disabled, an input sanitization flaw was
revealed in the Python string object implementation that led to a buffer
overflow. The missing check for negative size values meant the Python
memory allocator could allocate less memory than expected. This could
result in arbitrary code execution with the Python interpreter's
privileges. (CVE-2008-1887)

Multiple buffer and integer overflow flaws were found in the Python Unicode
string processing and in the Python Unicode and string object
implementations. An attacker could use these flaws to cause a denial of
service (Python application crash). (CVE-2008-3142, CVE-2008-5031)

Multiple integer overflow flaws were found in the Python imageop module. If
a Python application used the imageop module to process untrusted images,
it could cause the application to crash or, potentially, execute arbitrary
code with the Python interpreter's privileges. (CVE-2008-1679,
CVE-2008-4864)

Multiple integer underflow and overflow flaws were found in the Python
snprintf() wrapper implementation. An attacker could use these flaws to
cause a denial of service (memory corruption). (CVE-2008-3144)

Multiple integer overflow flaws were found in various Python modules. An
attacker could use these flaws to cause a denial of service (Python
application crash). (CVE-2008-2315, CVE-2008-3143)

An integer signedness error, leading to a buffer overflow, was found
in the Python zlib extension module. If a Python application requested
the negative byte count be flushed for a decompression stream, it could
cause the application to crash or, potentially, execute arbitrary code
with the Python interpreter's privileges. (CVE-2008-1721)

Red Hat would like to thank David Remahl of the Apple Product Security team
for responsibly reporting the CVE-2008-1679 and CVE-2008-2315 issues.

All Python users should upgrade to these updated packages, which contain
backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1177.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"python", rpm:"python~2.3.4~14.7.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.3.4~14.7.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.3.4~14.7.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.3.4~14.7.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.3.4~14.7.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.3.4~14.7.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
