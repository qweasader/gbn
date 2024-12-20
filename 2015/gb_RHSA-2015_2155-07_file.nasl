# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871502");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-20 06:25:16 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-3478",
                "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3538",
                "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117",
                "CVE-2014-9652", "CVE-2014-9653", "CVE-2012-1571");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for file RHSA-2015:2155-07");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'file'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The file command is used to identify a
particular file according to the  type of data the file contains. It can identify
many different file  types, including Executable and Linkable Format (ELF) binary
files, system libraries, RPM packages, and different graphics formats.

Multiple denial of service flaws were found in the way file parsed certain
Composite Document Format (CDF) files. A remote attacker could use either
of these flaws to crash file, or an application using file, via a specially
crafted CDF file. (CVE-2014-0207, CVE-2014-0237, CVE-2014-0238,
CVE-2014-3479, CVE-2014-3480, CVE-2014-3487, CVE-2014-3587)

Two flaws were found in the way file processed certain Pascal strings. A
remote attacker could cause file to crash if it was used to identify the
type of the attacker-supplied file. (CVE-2014-3478, CVE-2014-9652)

Multiple flaws were found in the file regular expression rules for
detecting various files. A remote attacker could use these flaws to cause
file to consume an excessive amount of CPU. (CVE-2014-3538)

Multiple flaws were found in the way file parsed Executable and Linkable
Format (ELF) files. A remote attacker could use these flaws to cause file
to crash, disclose portions of its memory, or consume an excessive amount
of system resources. (CVE-2014-3710, CVE-2014-8116, CVE-2014-8117,
CVE-2014-9653)

Red Hat would like to thank Thomas Jarosch of Intra2net AG for reporting
the CVE-2014-8116 and CVE-2014-8117 issues. The CVE-2014-0207,
CVE-2014-0237, CVE-2014-0238, CVE-2014-3478, CVE-2014-3479, CVE-2014-3480,
CVE-2014-3487, CVE-2014-3710 issues were discovered by Francisco Alonso of
Red Hat Product Security  the CVE-2014-3538 issue was discovered by Jan
Kalua of the Red Hat Web Stack Team

The file packages have been updated to ensure correct operation on Power
little endian and ARM 64-bit hardware architectures. (BZ#1224667,
BZ#1224668, BZ#1157850, BZ#1067688).

All file users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"file on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2155-07");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00027.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"python-magic", rpm:"python-magic~5.11~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"file", rpm:"file~5.11~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"file-debuginfo", rpm:"file-debuginfo~5.11~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"file-libs", rpm:"file-libs~5.11~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
