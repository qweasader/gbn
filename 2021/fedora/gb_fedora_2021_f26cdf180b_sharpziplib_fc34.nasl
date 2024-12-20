# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818589");
  script_version("2024-10-10T07:25:31+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2021-10-02 01:22:36 +0000 (Sat, 02 Oct 2021)");
  script_name("Fedora: Security Advisory for sharpziplib (FEDORA-2021-f26cdf180b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-f26cdf180b");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5Z7ROWJY5G7T5DBJHSLXKXH6KXD2X433");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sharpziplib'
  package(s) announced via the FEDORA-2021-f26cdf180b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SharpZipLib, formerly NZipLib is a Zip, GZip, Tar and BZip2 library
written entirely in C#. It is implemented as an assembly (installable
in the GAC), and thus can easily be incorporated into other projects.");

  script_tag(name:"affected", value:"'sharpziplib' package(s) on Fedora 34.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC34") {

  if(!isnull(res = isrpmvuln(pkg:"sharpziplib", rpm:"sharpziplib~1.3.3~0.fc34", rls:"FC34"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);