# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0106");
  script_cve_id("CVE-2022-44570", "CVE-2022-44571", "CVE-2022-44572", "CVE-2023-27530");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-16 16:18:23 +0000 (Thu, 16 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0106)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0106");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0106.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31496");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FJFU3ZHNAUDV7V7P7HFAAT4TJIHOMW5K/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-February/013629.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/014032.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5910-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3298");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-rack' package(s) announced via the MGASA-2023-0106 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service vulnerability in the Range header parsing component of
Rack >= 1.5.0. A Carefully crafted input can cause the Range header parsing
component in Rack to take an unexpected amount of time, possibly resulting
in a denial of service attack vector. Any applications that deal with Range
requests (such as streaming applications, or applications that serve files)
may be impacted. (CVE-2022-44570)

There is a denial of service vulnerability in the Content-Disposition
parsingcomponent of Rack fixed in 2.0.9.2, 2.1.4.2, 2.2.4.1, 3.0.0.1. This
could allow an attacker to craft an input that can cause Content-Disposition
header parsing in Rackto take an unexpected amount of time, possibly
resulting in a denial ofservice attack vector. This header is used typically
used in multipartparsing. Any applications that parse multipart posts using
Rack (virtuallyall Rails applications) are impacted. (CVE-2022-44571)

A denial of service vulnerability in the multipart parsing component of Rack
fixed in 2.0.9.2, 2.1.4.2, 2.2.4.1 and 3.0.0.1 could allow an attacker to
craft input that can cause RFC2183 multipart boundary parsing in Rack to
take an unexpected amount of time, possibly resulting in a denial of service
attack vector. Any applications that parse multipart posts using Rack
(virtually all Rails applications) are impacted. (CVE-2022-44572)

A DoS vulnerability exists in Rack <v3.0.4.2, <v2.2.6.3, <v2.1.4.3 and
<v2.0.9.3 within in the Multipart MIME parsing code in which could allow an
attacker to craft requests that can be abuse to cause multipart parsing to
take longer than expected. (CVE-2023-27530)");

  script_tag(name:"affected", value:"'ruby-rack' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"ruby-rack", rpm:"ruby-rack~2.2.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rack-doc", rpm:"ruby-rack-doc~2.2.3.1~1.2.mga8", rls:"MAGEIA8"))) {
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
