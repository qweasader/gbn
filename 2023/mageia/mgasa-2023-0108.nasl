# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0108");
  script_cve_id("CVE-2023-25563", "CVE-2023-25564", "CVE-2023-25565", "CVE-2023-25566", "CVE-2023-25567");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-22 18:39:00 +0000 (Wed, 22 Feb 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0108)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0108");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0108.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31574");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WXCOTOTL4ZIZB65QEGM65YZZILOED4A3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gssntlmssp' package(s) announced via the MGASA-2023-0108 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple out-of-bounds read when decoding NTLM fields. (CVE-2023-25563)
Memory corruption when decoding UTF16 strings. (CVE-2023-25564)
Incorrect free when decoding target information. (CVE-2023-25565)
Memory leak when parsing usernames. (CVE-2023-25566)
Out-of-bounds read when decoding target information. (CVE-2023-25567)");

  script_tag(name:"affected", value:"'gssntlmssp' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"gssntlmssp", rpm:"gssntlmssp~1.2.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gssntlmssp-devel", rpm:"gssntlmssp-devel~1.2.0~1.mga8", rls:"MAGEIA8"))) {
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
