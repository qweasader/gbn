# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1497");
  script_cve_id("CVE-2017-15994", "CVE-2017-16548", "CVE-2017-17433", "CVE-2018-5764");
  script_tag(name:"creation_date", value:"2020-04-16 05:58:37 +0000 (Thu, 16 Apr 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-28 20:30:02 +0000 (Tue, 28 Nov 2017)");

  script_name("Huawei EulerOS: Security Advisory for rsync (EulerOS-SA-2020-1497)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1497");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1497");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'rsync' package(s) announced via the EulerOS-SA-2020-1497 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The receive_xattr function in xattrs.c in rsync 3.1.2 and 3.1.3-development does not check for a trailing '\0' character in an xattr name, which allows remote attackers to cause a denial of service (heap-based buffer over-read and application crash) or possibly have unspecified other impact by sending crafted data to the daemon.(CVE-2017-16548)

The parse_arguments function in options.c in rsyncd in rsync before 3.1.3 does not prevent multiple --protect-args uses, which allows remote attackers to bypass an argument-sanitization protection mechanism.(CVE-2018-5764)

The recv_files function in receiver.c in the daemon in rsync 3.1.2, and 3.1.3-development before 2017-12-03, proceeds with certain file metadata updates before checking for a filename in the daemon_filter_list data structure, which allows remote attackers to bypass intended access restrictions.(CVE-2017-17433)

rsync 3.1.3-development before 2017-10-24 mishandles archaic checksums, which makes it easier for remote attackers to bypass intended access restrictions. NOTE: the rsync development branch has significant use beyond the rsync developers, e.g., the code has been copied for use in various GitHub projects.(CVE-2017-15994)");

  script_tag(name:"affected", value:"'rsync' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.1.2~4.h4.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
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
