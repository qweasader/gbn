# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.14898.1");
  script_cve_id("CVE-2019-19630", "CVE-2021-20308", "CVE-2022-0534");
  script_tag(name:"creation_date", value:"2022-03-01 03:33:37 +0000 (Tue, 01 Mar 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-09 12:52:43 +0000 (Fri, 09 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:14898-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:14898-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-202214898-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'htmldoc' package(s) announced via the SUSE-SU-2022:14898-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for htmldoc fixes the following issues:

CVE-2019-19630: Fixed stack-based buffer overflow in the hd_strlcpy()
 function in string.c via a crafted HTML document (bsc#1158802).

CVE-2021-20308: Fixed integer overflow in image_load_gif() (bsc#1184424).

CVE-2022-0534: Fixed stack out-of-bounds read in gif_get_code() when
 opening a malicious GIF file results in a segmentation fault
 (bsc#1195758).");

  script_tag(name:"affected", value:"'htmldoc' package(s) on SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"htmldoc", rpm:"htmldoc~1.8.27~170.4.9.1", rls:"SLES11.0SP3"))) {
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
