# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827502");
  script_version("2023-04-19T10:19:33+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-19 10:19:33 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-16 01:06:18 +0000 (Sun, 16 Apr 2023)");
  script_name("Fedora: Security Advisory for zchunk (FEDORA-2023-86dce75007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-86dce75007");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/F5RLR5ZMW37SYLGGMHGVQALE3AZC5CPT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zchunk'
  package(s) announced via the FEDORA-2023-86dce75007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"zchunk is a compressed file format that splits the file into independent
chunks.  This allows you to only download the differences when downloading a
new version of the file, and also makes zchunk files efficient over rsync.
zchunk files are protected with strong checksums to verify that the file you
downloaded is in fact the file you wanted.");

  script_tag(name:"affected", value:"'zchunk' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"zchunk", rpm:"zchunk~1.3.1~1.fc38", rls:"FC38"))) {
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