# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871862");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-08-04 12:46:55 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2014-9761", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778",
                "CVE-2015-8779");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-13 21:29:00 +0000 (Thu, 13 Jun 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for glibc RHSA-2017:1916-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The glibc packages provide the standard C
  libraries (libc), POSIX thread libraries (libpthread), standard math libraries
  (libm), and the name service cache daemon (nscd) used by multiple programs on
  the system. Without these libraries, the Linux system cannot function correctly.
  Security Fix(es): * A stack overflow vulnerability was found in nan* functions
  that could cause applications, which process long strings with the nan function,
  to crash or, potentially, execute arbitrary code. (CVE-2014-9761) * It was found
  that out-of-range time values passed to the strftime() function could result in
  an out-of-bounds memory access. This could lead to application crash or,
  potentially, information disclosure. (CVE-2015-8776) * An integer overflow
  vulnerability was found in hcreate() and hcreate_r() functions which could
  result in an out-of-bounds memory access. This could lead to application crash
  or, potentially, arbitrary code execution. (CVE-2015-8778) * A stack based
  buffer overflow vulnerability was found in the catopen() function. An
  excessively long string passed to the function could cause it to crash or,
  potentially, execute arbitrary code. (CVE-2015-8779) * It was found that the
  dynamic loader did not sanitize the LD_POINTER_GUARD environment variable. An
  attacker could use this flaw to bypass the pointer guarding protection on
  set-user-ID or set-group-ID programs to execute arbitrary code with the
  permissions of the user running the application. (CVE-2015-8777) Additional
  Changes: For detailed information on changes in this release, see the Red Hat
  Enterprise Linux 7.4 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"glibc on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:1916-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00011.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~196.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~196.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.17~196.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo-common", rpm:"glibc-debuginfo-common~2.17~196.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~196.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~196.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~196.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~196.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}